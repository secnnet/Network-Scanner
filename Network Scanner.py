#!/usr/bin/env python3

import os.path
import argparse
import subprocess
import re
import time
import logging


def open_file(parser, arg):
    """Custom type function to open and validate file existence."""
    file_path = arg
    if not os.path.exists(file_path):
        parser.error("The file %s does not exist!" % file_path)
    return file_path


def setup_logging(debug_mode):
    """Configure logging based on debug mode."""
    level = logging.DEBUG if debug_mode else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def scan_network(ip_array, max_concurrent_scans, sleep_seconds, debug_mode):
    """Perform network scanning using Nmap."""
    process_array = []
    running_scans = 0
    if max_concurrent_scans > len(ip_array):
        max_concurrent_scans = len(ip_array)

    while running_scans > 0 or len(ip_array) > 0:
        if running_scans < max_concurrent_scans:
            number_to_kickoff = max_concurrent_scans - running_scans
            if debug_mode:
                logging.debug("Kicking off %d scans.", number_to_kickoff)
            if len(ip_array) > 0:
                for _ in range(number_to_kickoff):
                    ip_address = ip_array[0]
                    filename = 'nmap-' + ip_address.replace('/', '-')
                    command = [
                        "nmap", "-A", "-R", "--reason", "--resolve-all", "-sS", "-sU", "-sV",
                        "--script=ssl-enum-ciphers",
                        "-p", "0,22,25,80,143,280,443,445,465,563,567,585,587,591,593,636,695,808,"
                               "832,898,981,989,990,992,993,994,995,1090,1098,1099,1159,1311,1360,"
                               "1392,1433,1434,1521,1527,1583,2083,2087,2096,2376,2484,2638,3071,"
                               "3131,3132,3269,3306,3351,3389,3424,3872,3873,4443,4444,4445,4446,"
                               "4843,4848,4903,5223,5432,5500,5556,5671,5672,5800,5900,5989,6080,"
                               "6432,6619,6679,6697,6701,6703,7000,7002,7004,7080,7091,7092,7101,"
                               "7102,7103,7105,7107,7109,7201,7202,7301,7306,7307,7403,7444,7501,"
                               "7777,7799,7802,8000,8009,8080,8081,8082,8083,8089,8090,8140,8191,"
                               "8243,8333,8443,8444,8531,8834,8888,8889,8899,9001,9002,9091,9095,"
                               "9096,9097,9098,9099,9100,9443,9999,10000,10109,10443,10571,10911,"
                               "11214,11215,12043,12443,12975,13722,17169,18091,18092,18366,19812,"
                               "20911,23051,23642,27724,31100,32100,32976,33300,33840,36210,37549,"
                               "38131,38760,41443,41581,41971,43778,46160,46393,49203,49223,49693,"
                               "49926,55130,55443,56182,57572,58630,60306,62657,63002,64779,65298",
                        "-oA", filename, ip_address
                    ]
                    if re.match(r"[0-9.]+/\d+", ip_address):
                        ip_address = ip_address.split('/')[0]
                        command[-2] = filename
                    try:
                        p = subprocess.Popen(command, stdout=subprocess.PIPE)
                        process_array.append(p)
                        del ip_array[0]
                    except subprocess.CalledProcessError as e:
                        logging.error("Error occurred while executing Nmap command: %s", e)
                        del ip_array[0]

        running_scans = sum(1 for p in process_array if p.poll() is None)
        logging.info('Running scans: %d', running_scans)
        time.sleep(sleep_seconds)


def process_scan_results():
    """Process the Nmap scan results and write to the final output file."""
    filenames = [f for f in os.listdir('.') if f.startswith('nmap') and f.endswith('.txt')]
    content = ''.join(open(f).read() for f in filenames)

    lines = re.findall(r"Port.*", content)

    with open('final.txt', 'w') as myfile:
        for line in lines:
            ip_addr = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line).group()
            port_fields = re.findall(r"(\d+)/(\w+)", line)
            for port, protocol in port_fields:
                output_line = f"{ip_addr},OPEN,{protocol.upper()},{port}"
                myfile.write(output_line + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--inputfile", dest="filename",
        help="Input file with IP addresses, one per line. Default name is targets.txt",
        metavar="FILE",
        type=lambda x: open_file(parser, x),
        default='targets.txt'
    )
    parser.add_argument(
        "-s", "--sleep", help="Amount of time in seconds to sleep between status checks",
        nargs='?', const=10, type=int, default=10
    )
    parser.add_argument(
        "-c", "--concurrent", help="Maximum number of concurrent processes allowed",
        nargs='?', const=3, type=int, default=3
    )
    parser.add_argument("-d", "--debug", help="Show debug messages", action="store_true")
    args = parser.parse_args()

    max_concurrent_scans = args.concurrent
    sleep_seconds = args.sleep
    file = args.filename
    debug_mode = args.debug

    setup_logging(debug_mode)

    logging.debug('File: %s', args.filename)
    logging.debug('Print debug messages: %s', debug_mode)
    logging.debug('Sleep %d seconds between status checks.', sleep_seconds)
    logging.debug('Maximum concurrent scans: %d', max_concurrent_scans)

    ip_array = [line.strip() for line in open(file)]

    scan_network(ip_array, max_concurrent_scans, sleep_seconds, debug_mode)
    process_scan_results()


if __name__ == '__main__':
    main()
