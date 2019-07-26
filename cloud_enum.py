#!/usr/bin/env python3

"""
cloud_enum by initstring (github.com/initstring)

Multi-cloud OSINT tool designed to find:

Storage Buckets:
- Amazon S3 buckets
- Azure Blob Storage
- Google Cloud Storage

Development sites:
- Azure

Enjoy!
"""

import os
import sys
import argparse
import re
from enum_tools import aws_checks
from enum_tools import azure_checks
from enum_tools import gcp_checks

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
    script_path = os.path.dirname(__file__)

    # Keyword can given multiple times
    parser.add_argument('-k', '--keyword', type=str, action='append',
                        required=True,
                        help='Keyword. Can use argument multiple times.')

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

    parser.add_argument('--disable-aws', action='store_true',
                        help='Disable Amazon checks.')

    parser.add_argument('--disable-azure', action='store_true',
                        help='Disable Azure checks.')

    parser.add_argument('--disable-gcp', action='store_true',
                        help='Disable Google checks.')

    args = parser.parse_args()

    # Ensure mutations file is readable
    if not os.access(args.mutations, os.R_OK):
        print("[!] Cannot access mutations file: {}"
              .format(args.mutations))
        sys.exit()

    # Ensure brute file is readable
    if not os.access(args.brute, os.R_OK):
        print("[!] Cannot access brute-force file, exiting")
        sys.exit()

    return args

def print_status(args):
    """
    Print a short pre-run status message
    """
    print("Keywords:    {}".format(', '.join(args.keyword)))
    print("Mutations:   {}".format(args.mutations))
    print("Brute-list:  {}".format(args.brute))
    print("")

def read_mutations(mutations_file):
    """
    Read mutations file into memory for processing.
    """
    with open(mutations_file, encoding="utf8", errors="ignore") as infile:
        mutations = infile.read().splitlines()

    print("[+] Mutations list imported: {} items".format(len(mutations)))
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
            names.append("{}{}".format(base, mutation))
            names.append("{}.{}".format(base, mutation))
            names.append("{}-{}".format(base, mutation))

            # Then, do prepends
            names.append("{}{}".format(mutation, base))
            names.append("{}.{}".format(mutation, base))
            names.append("{}-{}".format(mutation, base))

    print("[+] Mutated results: {} items".format(len(names)))

    return names

def main():
    """
    Main program function.
    """
    args = parse_arguments()

    print(BANNER)

    # Generate a basic status on targets and parameters
    print_status(args)

    # First, build a sort base list of target names
    mutations = read_mutations(args.mutations)
    names = build_names(args.keyword, mutations)

    # All the work is done in the individual modules
    if not args.disable_aws:
        aws_checks.run_all(names, args.threads)
    if not args.disable_azure:
        azure_checks.run_all(names, args.brute, args.threads, args.nameserver)
    if not args.disable_gcp:
        gcp_checks.run_all(names, args.threads)

    # Best of luck to you!
    print("\n[+] All done, happy hacking!\n")
    sys.exit()


if __name__ == '__main__':
    main()
