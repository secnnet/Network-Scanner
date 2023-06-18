# Network Scanner

This is a Python script that performs network scanning using Nmap. It allows you to scan multiple IP addresses simultaneously, control the number of concurrent scans, and customize the sleep interval between status checks.

## Prerequisites

- Python 3
- Nmap

## Installation

1. Clone the repository or download the script.
2. Make sure you have Python 3 and Nmap installed on your system.

## Usage

The script accepts the following command-line arguments:
    ```python network_scanner.py [-h] [-i FILE] [-s [SLEEP]] [-c [CONCURRENT]] [-d]
    ```

- `-h`, `--help`: Show the help message and exit.
- `-i FILE`, `--inputfile FILE`: Input file with IP addresses, one per line. Default name is `targets.txt`.
- `-s [SLEEP]`, `--sleep [SLEEP]`: Amount of time in seconds to sleep between status checks. Default is 10 seconds.
- `-c [CONCURRENT]`, `--concurrent [CONCURRENT]`: Maximum number of concurrent processes allowed. Default is 3.
- `-d`, `--debug`: Show debug messages.

Example usage:
    ```python network_scanner.py -i targets.txt -s 5 -c 5 -d
    ```

## How it works

1. The script reads a list of IP addresses from the input file.
2. It kicks off network scans using Nmap for each IP address.
3. The number of concurrent scans is controlled to avoid overloading the system.
4. Scans run asynchronously, and the script periodically checks the status of running scans.
5. The script processes the scan results and extracts open ports with their corresponding IP addresses, protocols, and port numbers.
6. The final output is written to a file named `final.txt`.

## Notes

- Nmap must be installed and accessible from the command line for the script to work properly.
- Make sure to provide a valid input file with one IP address per line.
- Adjust the sleep interval and maximum concurrent scans according to your system's capabilities and network conditions.

## License

This project is licensed under the [MIT License](LICENSE).
