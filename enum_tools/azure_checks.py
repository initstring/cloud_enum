"""
Azure-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import re
import requests
from enum_tools import utils
from enum_tools import azure_regions

BANNER = '''
++++++++++++++++++++++++++
       azure checks
++++++++++++++++++++++++++
'''

# Known Azure domain names
BLOB_URL = 'blob.core.windows.net'
WEBAPP_URL = 'azurewebsites.net'
DATABASE_URL = 'database.windows.net'

# Virtual machine DNS names are actually:
#   {whatever}.{region}.cloudapp.azure.com
VM_URL = 'cloudapp.azure.com'


def print_account_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    if reply.status_code == 404:
        pass
    elif 'Server failed to authenticate the request' in reply.reason:
        utils.printc("    Auth-Only Storage Account: {}\n"
                     .format(reply.url), 'red')
    elif 'The specified account is disabled' in reply.reason:
        utils.printc("    Disabled Storage Account: {}\n"
                     .format(reply.url), 'red')
    elif 'Value for one of the query' in reply.reason:
        utils.printc("    HTTP-OK Storage Account: {}\n"
                     .format(reply.url), 'orange')
    elif 'The account being accessed' in reply.reason:
        utils.printc("    HTTPS-Only Storage Account: {}\n"
                     .format(reply.url), 'orange')
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

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

    # de-dupe the results and return
    return list(set(valid_names))

def print_container_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    # Stop brute forcing disabled accounts
    if 'The specified account is disabled' in reply.reason:
        print("    [!] Breaking out early, account disabled.")
        return 'breakout'

    # Stop brute forcing accounts without permission
    if 'not authorized to perform this operation' in reply.reason:
        print("    [!] Breaking out early, auth errors.")
        return 'breakout'

    # Stop brute forcing unsupported accounts
    if 'Blob API is not yet supported' in reply.reason:
        print("    [!] Breaking out early, Hierarchical namespace account")
        return 'breakout'

    # Handle other responses
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        utils.printc("    OPEN AZURE CONTAINER: {}\n"
                     .format(reply.url), 'green')
        utils.list_bucket_contents(reply.url)
    elif 'One of the request inputs is out of range' in reply.reason:
        pass
    elif 'The request URI is invalid' in reply.reason:
        pass
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

def brute_force_containers(storage_accounts, brute_list, threads):
    """
    Attempts to find public Blob Containers in valid Storage Accounts

    Here is the URL format to list Azure Blog Container contents:
    <account>.blob.core.windows.net/<container>/?restype=container&comp=list
    """

    # We have a list of valid DNS names that might not be worth scraping,
    # such as disabled accounts or authentication required. Let's quickly
    # weed those out.
    print("[*] Checking {} accounts for status before brute-forcing"
          .format(len(storage_accounts)))
    valid_accounts = []
    for account in storage_accounts:
        reply = requests.get('https://{}/'.format(account))
        if 'Server failed to authenticate the request' in reply.reason:
            storage_accounts.remove(account)
        elif 'The specified account is disabled' in reply.reason:
            storage_accounts.remove(account)
        else:
            valid_accounts.append(account)

    # Read the brute force file into memory
    with open(brute_list, encoding="utf8", errors="ignore") as infile:
        names = infile.read().splitlines()

    # Clean up the names to usable for containers
    banned_chars = re.compile('[^a-z0-9-]')
    clean_names = []
    for name in names:
        name = name.lower()
        name = banned_chars.sub('', name)
        if 63 >= len(name) >= 3:
            if name not in clean_names:
                clean_names.append(name)

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    print("[*] Brute-forcing container names in {} storage accounts"
          .format(len(valid_accounts)))
    for account in valid_accounts:
        print("[*] Brute-forcing {} container names in {}"
              .format(len(clean_names), account))

        # Initialize the list of correctly formatted urls
        candidates = []

        # Take each mutated keyword and craft a url with correct format
        for name in clean_names:
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

def print_database_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    utils.printc("    Registered Azure Database DNS Name: {}\n"
                 .format(hostname), 'green')

def check_azure_databases(names, nameserver):
    """
    Checks for Azure Databases
    """
    print("[+] Checking for Azure Databases")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + DATABASE_URL for name in names]

    # Azure databases use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          callback=print_database_response)

    # Stop the timer
    utils.stop_timer(start_time)

def print_vm_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    utils.printc("    Registered Azure Virtual Machine DNS Name: {}\n"
                 .format(hostname), 'green')

def check_azure_vms(names, nameserver):
    """
    Checks for Azure Virtual Machines
    """
    print("[+] Checking for Azure Virtual Machines")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Pull the regions from a config file
    regions = azure_regions.REGIONS

    print("[*] Testing across {} regions defined in the config file"
          .format(len(regions)))

    for region in regions:

        # Initialize the list of domain names to look up
        candidates = [name + '.' + region + '.' + VM_URL for name in names]

        # Azure VMs use DNS sub-domains. If it resolves, it is registered.
        utils.fast_dns_lookup(candidates, nameserver,
                              callback=print_vm_response)

    # Stop the timer
    utils.stop_timer(start_time)

def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    valid_accounts = check_storage_accounts(names, args.threads,
                                            args.nameserver)
    if valid_accounts:
        brute_force_containers(valid_accounts, args.brute, args.threads)

    check_azure_websites(names, args.nameserver)
    check_azure_databases(names, args.nameserver)
    check_azure_vms(names, args.nameserver)
