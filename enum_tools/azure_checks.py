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
FILE_URL = 'file.core.windows.net'
QUEUE_URL = 'queue.core.windows.net'
TABLE_URL = 'table.core.windows.net'
MGMT_URL = 'scm.azurewebsites.net'
VAULT_URL = 'vault.azure.net'
WEBAPP_URL = 'azurewebsites.net'
DATABASE_URL = 'database.windows.net'

# Virtual machine DNS names are actually:
#   {whatever}.{region}.cloudapp.azure.com
VM_URL = 'cloudapp.azure.com'


class AzureChecks:
    def __init__(self, log, args, names):
        self.log = log
        self.args = args
        self.names = names

    def print_account_response(reply):
        """
        Parses the HTTP reply of a brute-force attempt

        This function is passed into the class object so we can view results
        in real-time.
        """
        data = {'platform': 'azure', 'msg': '',
                'target': '', 'access': '', 'key': ''}

        if reply.status_code == 404 or 'The requested URI does not represent' in reply.reason:
            pass
        elif 'Server failed to authenticate the request' in reply.reason:
            data['key'] = 'ACCOUNT_AUTH'
            data['msg'] = 'Auth-Only Account'
            data['target'] = reply.url
            data['access'] = 'protected'
            utils.fmt_output(data)
        elif 'The specified account is disabled' in reply.reason:
            data['key'] = 'ACCOUNT_DISABLED'
            data['msg'] = 'Disabled Account'
            data['target'] = reply.url
            data['access'] = 'disabled'
            utils.fmt_output(data)
        elif 'Value for one of the query' in reply.reason:
            data['key'] = 'ACCOUNT_HTTP_OK'
            data['msg'] = 'HTTP-OK Account'
            data['target'] = reply.url
            data['access'] = 'public'
            utils.fmt_output(data)
        elif 'The account being accessed' in reply.reason:
            data['key'] = 'ACCOUNT_HTTPS_ONLY'
            data['msg'] = 'HTTPS-Only Account'
            data['target'] = reply.url
            data['access'] = 'public'
            utils.fmt_output(data)
        elif 'Unauthorized' in reply.reason:
            data['key'] = 'ACCOUNT_UNAUTHORIZED'
            data['msg'] = 'Unathorized Account'
            data['target'] = reply.url
            data['access'] = 'public'
        else:
            print("    Unknown status codes being received from " + reply.url + ":\n"
                  "       " + str(reply.status_code)+" : " + reply.reason)

    def check_storage_accounts(self):
        """
        Checks storage account names
        """
        print("Checking for Azure Storage Accounts")

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
        for name in self.names:
            if not re.search(regex, name):
                candidates.append(f'{name}.{BLOB_URL}')

        # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
        valid_names = utils.fast_dns_lookup(
            candidates, self.args.nameserver, self.args.nameserverfile, threads=self.args.threads)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=self.print_account_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

        # de-dupe the results and return
        return list(set(valid_names))

    def check_file_accounts(self):
        """
        Checks File account names
        """
        print("Checking for Azure File Accounts")

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
        for name in self.names:
            if not re.search(regex, name):
                candidates.append(f'{name}.{FILE_URL}')

        # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
        valid_names = utils.fast_dns_lookup(
            candidates, self.args.nameserver, self.args.nameserverfile, threads=self.args.threads)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=self.print_account_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

        # de-dupe the results and return
        return list(set(valid_names))

    def check_queue_accounts(self):
        """
        Checks Queue account names
        """
        print("Checking for Azure Queue Accounts")

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
        for name in self.names:
            if not re.search(regex, name):
                candidates.append(f'{name}.{QUEUE_URL}')

        # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
        valid_names = utils.fast_dns_lookup(
            candidates, self.args.nameserver, self.args.nameserverfile, threads=self.args.threads)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=self.print_account_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

        # de-dupe the results and return
        return list(set(valid_names))

    def check_table_accounts(self):
        """
        Checks Table account names
        """
        print("Checking for Azure Table Accounts")

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
        for name in self.names:
            if not re.search(regex, name):
                candidates.append(f'{name}.{TABLE_URL}')

        # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
        valid_names = utils.fast_dns_lookup(
            candidates, self.args.nameserver, self.args.nameserverfile, threads=self.args.threads)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=self.print_account_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

        # de-dupe the results and return
        return list(set(valid_names))

    def check_mgmt_accounts(self):
        """
        Checks App Management account names
        """
        print("Checking for Azure App Management Accounts")

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
        for name in self.names:
            if not re.search(regex, name):
                candidates.append(f'{name}.{MGMT_URL}')

        # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
        valid_names = utils.fast_dns_lookup(
            candidates, self.args.nameserver, self.args.nameserverfile, threads=self.args.threads)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=self.print_account_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

        # de-dupe the results and return
        return list(set(valid_names))

    def check_vault_accounts(self):
        """
        Checks Key Vault account names
        """
        print("Checking for Azure Key Vault Accounts")

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
        for name in self.names:
            if not re.search(regex, name):
                candidates.append(f'{name}.{VAULT_URL}')

        # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
        valid_names = utils.fast_dns_lookup(
            candidates, self.args.nameserver, self.args.nameserverfile, threads=self.args.threads)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=self.print_account_response, threads=self.args.threads)

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
        data = {'platform': 'azure', 'msg': '',
                'target': '', 'access': '', 'key': ''}

        # Stop brute forcing disabled accounts
        if 'The specified account is disabled' in reply.reason:
            print("    [!] Breaking out early, account disabled.")
            return 'breakout'

        # Stop brute forcing accounts without permission
        if ('not authorized to perform this operation' in reply.reason or
                'not have sufficient permissions' in reply.reason or
                'Public access is not permitted' in reply.reason or
                'Server failed to authenticate the request' in reply.reason):
            print("    [!] Breaking out early, auth required.")
            return 'breakout'

        # Stop brute forcing unsupported accounts
        if 'Blob API is not yet supported' in reply.reason:
            print("    [!] Breaking out early, Hierarchical namespace account")
            return 'breakout'

        # Handle other responses
        if reply.status_code == 404:
            pass
        elif reply.status_code == 200:
            data['key'] = 'CONTAINER_OPEN'
            data['msg'] = 'OPEN AZURE CONTAINER'
            data['target'] = reply.url
            data['access'] = 'public'
            utils.fmt_output(data)
            utils.list_bucket_contents(reply.url)
        elif 'One of the request inputs is out of range' in reply.reason:
            pass
        elif 'The request URI is invalid' in reply.reason:
            pass
        else:
            print(f"    Unknown status codes being received from {reply.url}:\n"
                  f"       {reply.status_code}: {reply.reason}")

        return None

    def brute_force_containers(self, storage_accounts):
        """
        Attempts to find public Blob Containers in valid Storage Accounts

        Here is the URL format to list Azure Blog Container contents:
        <account>.blob.core.windows.net/<container>/?restype=container&comp=list
        """

        # We have a list of valid DNS names that might not be worth scraping,
        # such as disabled accounts or authentication required. Let's quickly
        # weed those out.
        print(
            f"[*] Checking {len(storage_accounts)} accounts for status before brute-forcing")
        valid_accounts = []
        for account in storage_accounts:
            try:
                reply = requests.get(f'https://{account}/')
                if 'Server failed to authenticate the request' in reply.reason:
                    storage_accounts.remove(account)
                elif 'The specified account is disabled' in reply.reason:
                    storage_accounts.remove(account)
                else:
                    valid_accounts.append(account)
            except requests.exceptions.ConnectionError as error_msg:
                print(f"    [!] Connection error on https://{account}:")
                print(error_msg)

        # Read the brute force file into memory
        clean_names = utils.get_brute(self.args.brute, mini=3)

        # Start a counter to report on elapsed time
        start_time = utils.start_timer()

        print(
            f"[*] Brute-forcing container names in {len(valid_accounts)} storage accounts")
        for account in valid_accounts:
            print(
                f"[*] Brute-forcing {len(clean_names)} container names in {account}")

            # Initialize the list of correctly formatted urls
            candidates = []

            # Take each mutated keyword and craft a url with correct format
            for name in clean_names:
                candidates.append(
                    f'{account}/{name}/?restype=container&comp=list')

            # Send the valid names to the batch HTTP processor
            utils.get_url_batch(
                candidates, use_ssl=True, callback=self.print_container_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

    def print_website_response(hostname):
        """
        This function is passed into the DNS brute force as a callback,
        so we can get real-time results.
        """
        data = {'platform': 'azure', 'msg': '',
                'target': '', 'access': '', 'key': ''}

        data['key'] = 'REGISTERED_WEBSITE_DNS'
        data['msg'] = 'Registered Azure Website DNS Name'
        data['target'] = hostname
        data['access'] = 'public'
        utils.fmt_output(data)

    def check_azure_websites(self):
        """
        Checks for Azure Websites (PaaS)
        """
        print("Checking for Azure Websites")

        # Start a counter to report on elapsed time
        start_time = utils.start_timer()

        # Initialize the list of domain names to look up
        candidates = [name + '.' + WEBAPP_URL for name in self.names]

        # Azure Websites use DNS sub-domains. If it resolves, it is registered.
        utils.fast_dns_lookup(candidates, self.args.nameserver, self.args.nameserverfile,
                              callback=self.print_website_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

    def print_database_response(hostname):
        """
        This function is passed into the DNS brute force as a callback,
        so we can get real-time results.
        """
        data = {'platform': 'azure', 'msg': '',
                'target': '', 'access': '', 'key': ''}

        data['key'] = 'REGISTERED_DATABASE_DNS'
        data['msg'] = 'Registered Azure Database DNS Name'
        data['target'] = hostname
        data['access'] = 'public'
        utils.fmt_output(data)

    def check_azure_databases(self):
        """
        Checks for Azure Databases
        """
        print("Checking for Azure Databases")
        # Start a counter to report on elapsed time
        start_time = utils.start_timer()

        # Initialize the list of domain names to look up
        candidates = [name + '.' + DATABASE_URL for name in self.names]

        # Azure databases use DNS sub-domains. If it resolves, it is registered.
        utils.fast_dns_lookup(candidates, self.args.nameserver, self.args.nameserverfile,
                              callback=self.print_database_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

    def print_vm_response(hostname):
        """
        This function is passed into the DNS brute force as a callback,
        so we can get real-time results.
        """
        data = {'platform': 'azure', 'msg': '',
                'target': '', 'access': '', 'key': ''}

        data['key'] = 'REGISTERED_VM_DNS'
        data['msg'] = 'Registered Azure Virtual Machine DNS Name'
        data['target'] = hostname
        data['access'] = 'public'
        utils.fmt_output(data)

    def check_azure_vms(self):
        """
        Checks for Azure Virtual Machines
        """
        print("Checking for Azure Virtual Machines")

        # Start a counter to report on elapsed time
        start_time = utils.start_timer()

        # Pull the regions from a config file
        regions = azure_regions.REGIONS

        # If a region is specified, use that instead
        if self.args.region:
            regions = [self.args.region]

        print(
            f"[*] Testing across {len(regions)} regions defined in the config file or command line")

        for region in regions:
            # Initialize the list of domain names to look up
            candidates = [name + '.' + region +
                          '.' + VM_URL for name in self.names]

            # Azure VMs use DNS sub-domains. If it resolves, it is registered.
            utils.fast_dns_lookup(candidates, self.args.nameserver, self.args.nameserverfile,
                                  callback=self.print_vm_response, threads=self.args.threads)

        # Stop the timer
        utils.stop_timer(start_time)

    def run_all(self):
        """
        Function is called by main program
        """
        print(BANNER)

        valid_accounts = self.check_storage_accounts()
        if valid_accounts and not self.args.quickscan:
            self.brute_force_containers(self, valid_accounts)

        self.check_file_accounts()
        self.check_queue_accounts()
        self.check_table_accounts()
        self.check_mgmt_accounts()
        self.check_vault_accounts()

        self.check_azure_websites()
        self.check_azure_databases()
        self.check_azure_vms()
