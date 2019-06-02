"""
Azure-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import re
from cloud_enum import utils

BANNER = '''
++++++++++++++++++++++++++
       azure checks
++++++++++++++++++++++++++
'''

# Known Azure domain names
BLOB_URL = 'blob.core.windows.net'
WEBAPP_URL = 'azurewebsites.net'

def print_account_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    # 
    if reply.status_code == 404:
        pass
    elif 'The specified account is disabled' in reply.reason:
        utils.printc("    Disabled Storage Account: {}\n"
                     .format(reply.url), 'orange')
    elif 'Value for one of the query' in reply.reason:
        utils.printc("    HTTP-OK Storage Account: {}\n"
                     .format(reply.url), 'orange')
    elif 'The account being accessed' in reply.reason:
        utils.printc("    HTTPS-Only Storage Account: {}\n"
                     .format(reply.url), 'orange')
    else: print("    Unknown status codes being received:\n"
                "       {}: {}"
                .format(reply.status_code, reply.reason))

def check_storage_accounts(names, threads, nameserver):
    """
    Checks storage account names
    """
    print("[+] Checking for Azure Storage Accounts")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append('{}.{}'.format(name, BLOB_URL))

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

    return valid_names

def print_container_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    # Stop brute forcing disabled accounts
    if 'The specified account is disabled' in reply.reason:
        return 'breakout'

    # Stop brute forcing accounts without permission
    if 'not authorized to perform this operation' in reply.reason:
        return 'breakout'

    # Handle other responses
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        utils.printc("    OPEN AZURE CONTAINER: {}\n"
                     .format(reply.url), 'green')
    elif 'One of the request inputs is out of range' in reply.reason:
        pass
    else: print("    Unknown status codes being received:\n"
                "       {}: {}"
                .format(reply.status_code, reply.reason))

def brute_force_containers(storage_accounts, brute_list, threads):
    """
    Attempts to find public Blob Containers in valid Storage Accounts

    Here is the URL format to list Azure Blog Container contents:
    <account>.blob.core.windows.net/<container>/?restype=container&comp=list
    """
    # Read the brute force file into memory
    with open(brute_list) as infile:
        names = infile.read().splitlines()

    print("[+] Brute-forcing {} container names in each valid account"
          .format(len(names)))

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    for account in storage_accounts:
        # Initialize the list of correctly formatted urls
        candidates = []

        # Take each mutated keyword and craft a url with correct format
        for name in names:
            candidates.append('{}/{}/?restype=container&comp=list'
                              .format(account, name))

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=True,
                            callback=print_container_response,
                            threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

def print_website_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    utils.printc("    Registered Azure Website DNS Name: {}\n"
                 .format(hostname), 'green')

def check_azure_websites(names, nameserver):
    """
    Checks for Azure Websites (PaaS)
    """
    print("[+] Checking for Azure Websites")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + WEBAPP_URL for name in names]

    # Azure Websites use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          callback=print_website_response)

    # Stop the timer
    utils.stop_timer(start_time)

def run_all(names, brute_list, threads, nameserver):
    """
    Function is called by main program
    """
    print(BANNER)

    valid_accounts = check_storage_accounts(names, threads, nameserver)
    if valid_accounts:
        brute_force_containers(valid_accounts, brute_list, threads)

    check_azure_websites(names, nameserver)
