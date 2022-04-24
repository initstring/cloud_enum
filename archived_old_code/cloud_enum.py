#!/usr/bin/env python3

"""
cloud_enum by initstring (github.com/initstring)

Multi-cloud OSINT tool designed to enumerate storage and services in AWS,
Azure, and GCP.

Enjoy!
"""

import os
import sys
import argparse
import re
from enum_tools import aws_checks
from enum_tools import azure_checks
from enum_tools import gcp_checks
from enum_tools import utils

BANNER = '''
##########################
        cloud_enum
   github.com/initstring
##########################

'''


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
                        default=script_path + '/enum_tools/fuzz.txt',
                        help='Mutations. Default: enum_tools/fuzz.txt')

    # Use include container brute-force or let the user provide one
    parser.add_argument('-b', '--brute', type=str, action='store',
                        default=script_path + '/enum_tools/fuzz.txt',
                        help='List to brute-force Azure container names.'
                        '  Default: enum_tools/fuzz.txt')

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
        utils.init_logfile(args.logfile, args.format)

    return args


def print_status(args):
    """
    Print a short pre-run status message
    """
    print(f"Keywords:    {', '.join(args.keyword)}")
    if args.quickscan:
        print("Mutations:   NONE! (Using quickscan)")
    else:
        print(f"Mutations:   {args.mutations}")
    print(f"Brute-list:  {args.brute}")
    print("")


def check_windows():
    """
    Fixes pretty color printing for Windows users. Keeping out of
    requirements.txt to avoid the library requirement for most users.
    """
    if os.name == 'nt':
        try:
            import colorama
            colorama.init()
        except ModuleNotFoundError:
            print("[!] Yo, Windows user - if you want pretty colors, you can"
                  " install the colorama python package.")


def read_mutations(mutations_file):
    """
    Read mutations file into memory for processing.
    """
    with open(mutations_file, encoding="utf8", errors="ignore") as infile:
        mutations = infile.read().splitlines()

    print(f"[+] Mutations list imported: {len(mutations)} items")
    return mutations


def clean_text(text):
    """
    Clean text to be RFC compliant for hostnames / DNS
    """
    banned_chars = re.compile('[^a-z0-9.-]')
    text_lower = text.lower()
    text_clean = banned_chars.sub('', text_lower)

    return text_clean


def build_names(base_list, mutations):
    """
    Combine base and mutations for processing by individual modules.
    """
    names = []

    for base in base_list:
        # Clean base
        base = clean_text(base)

        # First, include with no mutations
        names.append(base)

        for mutation in mutations:
            # Clean mutation
            mutation = clean_text(mutation)

            # Then, do appends
            names.append(f"{base}{mutation}")
            names.append(f"{base}.{mutation}")
            names.append(f"{base}-{mutation}")

            # Then, do prepends
            names.append(f"{mutation}{base}")
            names.append(f"{mutation}.{base}")
            names.append(f"{mutation}-{base}")

    print(f"[+] Mutated results: {len(names)} items")

    return names


def main():
    """
    Main program function.
    """
    args = parse_arguments()
    print(BANNER)

    # Generate a basic status on targets and parameters
    print_status(args)

    # Give our Windows friends a chance at pretty colors
    check_windows()

    # First, build a sorted base list of target names
    if args.quickscan:
        mutations = []
    else:
        mutations = read_mutations(args.mutations)
    names = build_names(args.keyword, mutations)

    # All the work is done in the individual modules
    try:
        if not args.disable_aws:
            aws_checks.run_all(names, args)
        if not args.disable_azure:
            azure_checks.run_all(names, args)
        if not args.disable_gcp:
            gcp_checks.run_all(names, args)
    except KeyboardInterrupt:
        print("Thanks for playing!")
        sys.exit()

    # Best of luck to you!
    print("\n[+] All done, happy hacking!\n")
    sys.exit()


if __name__ == '__main__':
    main()
