"""
This module will contain basic utilities and helper functions
"""

import re


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
