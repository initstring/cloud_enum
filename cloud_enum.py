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
from cloud_enum import aws_checks
from cloud_enum import azure_checks
from cloud_enum import gcp_checks

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

    # Keyword can given multiple times
    parser.add_argument('-k', '--keyword', type=str, action='append',
                        required=True,
                        help='Keyword. Can use argument multiple times.')

    # Use included mutations file by default, or let the user provide one
    parser.add_argument('-m', '--mutations', type=str, action='store',
                        default='cloud_enum/mutations.txt',
                        help='Mutations. Default: cloud_enum/mutations.txt.')

    # Use include container brute-force or let the user provide one
    parser.add_argument('-b', '--brute', type=str, action='store',
                        default='cloud_enum/brute.txt',
                        help='List to brute-force Azure container names.'
                        '  Default: cloud_enum/brute.txt.')

    # Allow the user to specify a custom AWS region (NOT YET IMPLEMENTED)
    #parser.add_argument('-ar', '--aws_region', type=str, action='append',
    #                    help='Limit to specific AWS region/s (see list in'
    #                    ' aws_checks source code). Defaults to all regions.'
    #                    ' Can use argument multiple times.')

    args = parser.parse_args()

    #if args.aws_region:
    #    for region in args.aws_region:
    #        if region not in aws_checks.AWS_REGIONS:
    #            print("[!] Unknown region {}, exiting.".format(region))
    #            sys.exit()

    # Ensure mutations file is readable
    if not os.access(args.mutations, os.R_OK):
        print("[!] Cannot access mutations file, exiting")
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
    with open(mutations_file) as infile:
        mutations = infile.read().splitlines()

    print("[+] Mutations list imported: {} items".format(len(mutations)))
    return mutations

def build_names(base_list, mutations):
    """
    Combine base and mutations for processing by individual modules.
    """
    names = []

    for base in base_list:
        # First, include with no mutations
        names.append(base)

        for mutation in mutations:
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
    aws_checks.run_all(names)
    azure_checks.run_all(names, args.brute)
    gcp_checks.run_all(names)

    # Best of luck to you!
    print("\n[+] All done, happy hacking!\n")


if __name__ == '__main__':
    main()
