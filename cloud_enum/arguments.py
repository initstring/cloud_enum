"""
This module contains the argparser.
"""

import os
import sys
import argparse


def parse_arguments():
    """
    Handles user-passed parameters
    """
    desc = "Multi-cloud enumeration utility. All hail OSINT!"
    parser = argparse.ArgumentParser(description=desc)

    # Grab the current dir of the script, for setting some defaults below
    script_path = os.path.split(os.path.abspath(sys.argv[0]))[0]

    kw_group = parser.add_mutually_exclusive_group(required=True)

    # Keyword can given multiple times
    kw_group.add_argument('-k', '--keyword', type=str, action='append',
                          help='Keyword. Can use argument multiple times.')

    # OR, a keyword file can be used
    kw_group.add_argument('-kf', '--keyfile', type=str, action='store',
                          help='Input file with a single keyword per line.')

    # Use included mutations file by default, or let the user provide one
    parser.add_argument('-m', '--mutations', type=str, action='store',
                        default=script_path + '/fuzz.txt',
                        help='Mutations. Default: fuzz.txt')

    # Use include container brute-force or let the user provide one
    parser.add_argument('-b', '--brute', type=str, action='store',
                        default=script_path + '/fuzz.txt',
                        help='List to brute-force Azure container names.'
                        '  Default: fuzz.txt')

    parser.add_argument('-t', '--threads', type=int, action='store',
                        default=5, help='Threads for HTTP brute-force.'
                        ' Default = 5')

    parser.add_argument('-ns', '--nameserver', type=str, action='store',
                        default='8.8.8.8',
                        help='DNS server to use in brute-force.')

    parser.add_argument('-l', '--logfile', type=str, action='store',
                        help='Appends found items to specified file.')
    parser.add_argument('-f', '--format', type=str, action='store',
                        default='text',
                        help='Format for log file (text,json,csv)'
                             ' - default: text')

    parser.add_argument('--disable-aws', action='store_true',
                        help='Disable Amazon checks.')

    parser.add_argument('--disable-azure', action='store_true',
                        help='Disable Azure checks.')

    parser.add_argument('--disable-gcp', action='store_true',
                        help='Disable Google checks.')

    parser.add_argument('-qs', '--quickscan', action='store_true',
                        help='Disable all mutations and second-level scans')

    args = parser.parse_args()

    # Ensure mutations file is readable
    if not os.access(args.mutations, os.R_OK):
        print(f"[!] Cannot access mutations file: {args.mutations}")
        sys.exit()

    # Ensure brute file is readable
    if not os.access(args.brute, os.R_OK):
        print("[!] Cannot access brute-force file, exiting")
        sys.exit()

    # Ensure keywords file is readable
    if args.keyfile:
        if not os.access(args.keyfile, os.R_OK):
            print("[!] Cannot access keyword file, exiting")
            sys.exit()

        # Parse keywords from input file
        with open(args.keyfile, encoding='utf-8') as infile:
            args.keyword = [keyword.strip() for keyword in infile]

    # Ensure log file is writeable
    if args.logfile:
        if os.path.isdir(args.logfile):
            print("[!] Can't specify a directory as the logfile, exiting.")
            sys.exit()
        if os.path.isfile(args.logfile):
            target = args.logfile
        else:
            target = os.path.dirname(args.logfile)
            if target == '':
                target = '.'

        if not os.access(target, os.W_OK):
            print("[!] Cannot write to log file, exiting")
            sys.exit()

        # Set up logging format
        if args.format not in ('text', 'json', 'csv'):
            print("[!] Sorry! Allowed log formats: 'text', 'json', or 'csv'")
            sys.exit()
        # Set the global in the utils file, where logging needs to happen
        # utils.init_logfile(args.logfile, args.format)

    return args
