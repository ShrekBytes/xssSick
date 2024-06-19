# xssSick

xssSick is a Python script that can identify potential Cross-Site Scripting (XSS) vulnerabilities. It reads URLs from a given file, modifies the parameters of each URL with a gibberish value, brackets & signs, and searches the response for reflections and matches. If any reflections and matches are found, the script saves the URLs to an output file.

## Features

- Reads URLs from a file.
- Modifies each URL's parameters with a specific test value containing brackets and signs.
- Sends HTTP requests to the modified URLs.
- Searches the response source code for specific words and signs that indicate XSS possibilities.
- Saves the URLs where matches are found to an output file.
- Displays output in the terminal: `blue` for processed URLs, `red` for unreachable URLs, and `green` for matches (XSS) found.

## Requirements

- Python 3.x
- `requests` library
- `colorama` library

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/xssSick.git
   ```
2. Navigate to the project directory:
   ```sh
   cd xssSick
   ```
3. Install the required Python libraries:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

1. Run the script:
   ```sh
   python3 xssSick.py example.com.txt
   ```

2. The script will process each URL and save the results to an output file named `<domain>_found_urls.txt` (e.g., `example_found_urls.txt`).

## Contributing

Feel free to submit issues or pull requests if you have suggestions for improvements or find any bugs.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

By using this script, you agree that it is for educational purposes only and you have permission to test the URLs you provide. Misuse of this tool can lead to serious consequences. Always obtain proper authorization before testing.
