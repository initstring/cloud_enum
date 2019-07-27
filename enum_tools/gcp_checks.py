"""
Google-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils

BANNER = '''
++++++++++++++++++++++++++
      google checks
++++++++++++++++++++++++++
'''

# Known S3 domain names
GCP_URL = 'storage.googleapis.com'
APPSPOT_URL = 'appspot.com'

def print_bucket_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        utils.printc("    OPEN GOOGLE BUCKET: {}\n"
                     .format(reply.url), 'green')
        utils.list_bucket_contents(reply.url + '/')
    elif reply.status_code == 403:
        utils.printc("    Protected Google Bucket: {}\n"
                     .format(reply.url), 'orange')
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

def check_gcp_buckets(names, threads):
    """
    Checks for open and restricted Google Cloud buckets
    """
    print("[+] Checking for Google buckets")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        candidates.append('{}/{}'.format(GCP_URL, name))

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_bucket_response,
                        threads=threads)

    # Stop the time
    utils.stop_timer(start_time)

def print_appspot_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    if reply.status_code == 404:
        pass
    if reply.status_code == 500 or reply.status_code == 503:
        utils.printc("    Google App Engine app with a 50x error: {}\n"
                     .format(reply.url), 'orange')
    elif reply.status_code == 200 or reply.status_code == 302:
        utils.printc("    Google App Engine app: {}\n"
                     .format(reply.url), 'green')
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

def check_appspot(names, threads):
    """
    Checks for Google App Engine sites running on appspot.com
    """
    print("[+] Checking for Google App Engine apps")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # App Engine project names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append('{}.{}'.format(name, APPSPOT_URL))

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_appspot_response,
                        threads=threads)

    # Stop the time
    utils.stop_timer(start_time)

def run_all(names, threads):
    """
    Function is called by main program
    """
    print(BANNER)

    check_gcp_buckets(names, threads)
    check_appspot(names, threads)
    return ''
