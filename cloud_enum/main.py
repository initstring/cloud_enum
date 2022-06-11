"""
cloud_enum by initstring
https://github.com/initstring/cloud_enum

MIT License

Multi-cloud OSINT tool designed to enumerate storage and services in AWS,
Azure, and GCP.

Please enjoy responsibly.
"""

from cloud_enum import arguments
from cloud_enum import utils


BANNER = '''
##########################
        cloud_enum
   github.com/initstring
##########################

'''


def main():
    args = arguments.parse_arguments()

    print(BANNER)

    # Generate a basic status on targets and parameters
    utils.print_status(args)

    # First, build a sorted base list of target names
    if args.quickscan:
        mutations = []
    else:
        mutations = utils.read_mutations(args.mutations)
    names = utils.build_names(args.keyword, mutations)


if __name__ == "__main__":
    main()
