import os
import sys
import requests
from colorama import init, Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# Reads match words from a file and returns a list
def read_match_words_from_file(match_file_path):
    try:
        with open(match_file_path, "r") as match_file:
            match_words = [line.strip() for line in match_file]
        return match_words
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return []


# Modifies a query parameter in the given URL and returns the modified URL
def modify_query_param(url, param_name, new_value):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    query_params[param_name] = [new_value]
    parsed_url = list(parsed_url)
    parsed_url[4] = urlencode(query_params, doseq=True)
    modified_url = urlunparse(parsed_url)
    return modified_url


# SOURCES = [
#     "document.URL",
#     "document.documentURI",
#     "document.baseURI",
#     "location",
#     "document.cookie",
#     "document.referrer",
#     "window.name",
#     "history.pushState",
#     "history.replaceState",
# ]
#
# SINKS = [
#     "document.write",
#     "window.location",
#     "document.domain",
#     "element.innerHTML",
#     "element.setAttribute",
#     "location",
#     "element.outerHTML",
#     "element.insertAdjacentHTML",
#     "element.onevent",
#     "eval",
# ]
#
#
# # Searches for combinations of 'sink' and 'source' in the response text and writes to the output file
# def dom_possible(response, output_file):
#     response_text_lower = response.text.lower()
#     for sink in SINKS:
#         sink_lower = sink.lower()
#         if sink_lower in response_text_lower:
#             for source in SOURCES:
#                 source_lower = source.lower()
#                 if source_lower in response_text_lower and not (
#                     "location" in sink_lower and "location" in source_lower
#                 ):
#                     output_file.write(f"{sink:22} {source:22} {response.url}\n")
#                     output_file.flush()  # Ensure data is written immediately
#                     return  # Exit function after first match


# Searches for words in a webpage and writes results to the output file
def search_words_in_webpage(url, search_words, user_agent, output_file, timeout=23):
    try:
        # Set up a session with user agent
        with requests.Session() as session:
            session.headers = {"User-Agent": user_agent}

            # Fetch the webpage content with user agent and timeout, allowing redirects
            response = session.get(url, timeout=timeout, allow_redirects=True)
            response.raise_for_status()

            # dom_possible(response, output_file)

            # Check if any of the search words are present in the source code
            for search_word in search_words:
                if search_word.lower() in response.text.lower():
                    print(Fore.GREEN + str(urls_processed), end=" ")
                    output_file.write(f"{search_word:22} {response.url}\n")
                    output_file.flush()  # Ensure the content is written immediately

            # Check for redirects
            if response.url != url:
                # dom_possible(response, output_file)

                # Check the source code of the redirected page
                for search_word in search_words:
                    if search_word.lower() in response.text.lower():
                        print(Fore.GREEN + str(urls_processed), end=" ")
                        output_file.write(
                            f"{search_word:22} origin:{url} landed:{response.url}\n"
                        )
                        output_file.flush()  # Ensure the content is written immediately

    except requests.exceptions.RequestException:
        print(
            Fore.RED + str(urls_processed), end=" "
        )  # print(f"Failed to fetch: {url}")


def main():
    global urls_processed
    urls_processed = 0

    # Check if the correct number of arguments is provided
    if len(sys.argv) != 2:
        print("Usage: python3 script_name.py example.com.txt")
        sys.exit(1)

    # Get the txt file of URLs from command-line arguments
    file = sys.argv[1]
    domain = os.path.splitext(os.path.basename(file))[0]
    output_file_path = domain + "_found_urls.txt"

    # Initialize colorama
    init(autoreset=True)

    try:
        # count the total number of URLs
        with open(file, "r") as url_file:
            total_urls = sum(1 for line in url_file if line.strip())

        print(f"Total URLs to check for XSS: {total_urls}")

        # process each URL
        with open(output_file_path, "a") as output_file:
            with open(file, "r") as url_file:
                for line in url_file:
                    url = line.strip()

                    # Skip empty lines
                    if not url:
                        continue

                    urls_processed += 1
                    print(Fore.BLUE + str(urls_processed), end=" ")
                    for param_name, param_values in parse_qs(
                        urlparse(url).query, keep_blank_values=True
                    ).items():
                        new_value = r"""asdf">/<"""
                        modified_url = modify_query_param(url, param_name, new_value)
                        search_words_in_webpage(
                            modified_url, MATCH_WORDS, USER_AGENT, output_file
                        )

        print("\nAll URLs processed. Found URLs saved to", output_file_path)

    except FileNotFoundError:
        print(f"The file {file} does not exist.")
    except IOError:
        print(f"An I/O error occurred while accessing the file {file}.")


# Constants
MATCH_FILE_PATH = "match.txt"
MATCH_WORDS = read_match_words_from_file(MATCH_FILE_PATH)
USER_AGENT = r"""Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0"""

if __name__ == "__main__":
    main()
