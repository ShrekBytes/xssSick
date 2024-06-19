import os
import sys
import requests
from colorama import Fore, Style, init
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Check if the correct number of arguments is provided
if len(sys.argv) != 2:
    print("Usage: python3 script_name.py example.com.txt")
    sys.exit(1)

# Get the txt file of urls from command-line arguments
file = sys.argv[1]

# Extracts domain name
domain, _ = os.path.splitext(os.path.basename(file))

# Initialize colorama
init(autoreset=True)


def read_match_words_from_file(match_file_path):
    """Reads match words from a file and returns a list."""
    try:
        with open(match_file_path, "r") as match_file:
            # Read and strip each line in the file
            match_words = [line.strip() for line in match_file]
        return match_words
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return []


def modify_query_param(url, param_name, new_value):
    """Modifies a query parameter in the given URL and returns the modified URL."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    query_params[param_name] = [new_value]
    parsed_url = list(parsed_url)
    parsed_url[4] = urlencode(query_params, doseq=True)
    modified_url = urlunparse(parsed_url)
    return modified_url


def dom_possible(sinks, sources, response, output_file):
    # Finds the first combination of 'sink' and 'source' in the origin url.
    # Writes the formatted output to the file and breaks out of both loops when a match is found.
    for sink in sinks:
        if sink.lower() in response.text.lower():
            for source in sources:
                if source.lower() in response.text.lower() and not (
                    "location" in sink and "location" in source
                ):
                    output_file.write(f"{sink:22} {source:22} {response.url}\n")
                    output_file.flush()
                    return


def search_words_in_webpage(url, search_words, user_agent, output_file, timeout=23):
    """Searches for words in a webpage and writes results to the output file."""
    try:
        # Set up a session with user agent
        with requests.Session() as session:
            session.headers = {"User-Agent": user_agent}

            # Fetch the webpage content with user agent and timeout, allowing redirects
            response = session.get(url, timeout=timeout, allow_redirects=True)
            response.raise_for_status()

            # dom_possible(SINKS, SOURCES, response, output_file)

            # Check if any of the search words are present in the source code
            for search_word in search_words:
                if search_word.lower() in response.text.lower():
                    found_text = f"The word '{search_word}' was found."
                    # Print the found text in green and the match word in red
                    print(
                        Fore.GREEN
                        + found_text.replace(
                            search_word, Fore.RED + search_word + Fore.GREEN
                        )
                        + Style.RESET_ALL
                    )
                    output_file.write(
                        f"{search_word:22} {response.url}\n"
                    )  # Use response.url for the final URL
                    output_file.flush()  # Ensure the content is written immediately

            # Check for redirects
            if response.url != url:
                # dom_possible(SINKS, SOURCES, response, output_file)

                # Check the source code of the redirected page
                for search_word in search_words:
                    if search_word.lower() in response.text.lower():
                        found_text = f"The word '{search_word}' was found in the redirected page."
                        print(
                            Fore.GREEN
                            + found_text.replace(
                                search_word, Fore.RED + search_word + Fore.GREEN
                            )
                            + Style.RESET_ALL
                        )
                        output_file.write(
                            f"{search_word:22} origin:{url} landed:{response.url}\n"
                        )
                        output_file.flush()  # Ensure the content is written immediately

    except requests.exceptions.RequestException:
        print(f"Failed to fetch: {url}")


def search_words_in_multiple_urls(
    url_file_path, match_file_path, user_agent, output_file_path
):
    """Searches for words in multiple URLs and saves the results to a file."""
    try:
        # Read URLs from file
        with open(url_file_path, "r") as url_file:
            urls = [line.strip() for line in url_file]

        # Read match words from file
        match_words = read_match_words_from_file(match_file_path)

        total_urls = len(urls)
        urls_processed = 0

        # Save found URLs to a text file
        with open(output_file_path, "a") as output_file:
            # Test each URL for the presence of search words
            for url in urls:
                urls_processed += 1
                print(f"\nProcessing URL {urls_processed} of {total_urls}")
                print(f"Current URL: {url}")
                for param_name, param_values in parse_qs(
                    urlparse(url).query, keep_blank_values=True
                ).items():
                    new_value = r"""asdf">/<"""
                    modified_url = modify_query_param(url, param_name, new_value)
                    search_words_in_webpage(
                        modified_url, match_words, user_agent, output_file
                    )

        print("\nAll URLs processed. Found URLs saved to", output_file_path)

    except FileNotFoundError as e:
        print(f"Error: {e}")


# Define constants
MATCH_FILE_PATH = "match.txt"
SOURCES = [
    "document.URL",
    "document.documentURI",
    "document.baseURI",
    "location",
    "document.cookie",
    "document.referrer",
    "window.name",
    "history.pushState",
    "history.replaceState",
    "localStorage",
    "sessionStorage",
]
SINKS = [
    "document.write",
    "window.location",
    "document.domain",
    "element.innerHTML",
    "element.setAttribute",
    "location",
    "element.outerHTML",
    "element.insertAdjacentHTML",
    "element.onevent",
    "eval",
]
USER_AGENT = r"""Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0"""
OUTPUT_FILE_PATH = domain + "_found_urls.txt"

# Starts the program
search_words_in_multiple_urls(file, MATCH_FILE_PATH, USER_AGENT, OUTPUT_FILE_PATH)
