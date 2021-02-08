"""
Google-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils
from enum_tools import gcp_regions
from enum_tools import settings

BANNER = '''
++++++++++++++++++++++++++
      google checks
++++++++++++++++++++++++++
'''

# Known GCP domain names
GCP_URL = 'storage.googleapis.com'
FBRTDB_URL = 'firebaseio.com'
APPSPOT_URL = 'appspot.com'
FUNC_URL = 'cloudfunctions.net'

# Hacky, I know. Used to store project/region combos that report at least
# one cloud function, to brute force later on
HAS_FUNCS = []

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
        settings.results["gcp"]["bucket"]["open"].append(reply.url)
        utils.list_bucket_contents(reply.url + '/')
    elif reply.status_code == 403:
        utils.printc("    Protected Google Bucket: {}\n"
                     .format(reply.url), 'orange')
        settings.results["gcp"]["bucket"]["protected"].append(reply.url)
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

def print_fbrtdb_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        utils.printc("    OPEN GOOGLE FIREBASE RTDB: {}\n"
                     .format(reply.url), 'green')
        settings.results["gcp"]["firebase"]["open"].append(reply.url)
    elif reply.status_code == 401:
        utils.printc("    Protected Google Firebase RTDB: {}\n"
                     .format(reply.url), 'orange')
        settings.results["gcp"]["firebase"]["protected"].append(reply.url)
        
    elif reply.status_code == 402:
        utils.printc("    Payment required on Google Firebase RTDB: {}\n"
                     .format(reply.url), 'orange')
        settings.results["gcp"]["firebase"]["payment"].append(reply.url)
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

def check_fbrtdb(names, threads):
    """
    Checks for Google Firebase RTDB
    """
    print("[+] Checking for Google Firebase Realtime Databases")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # Firebase RTDB names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append('{}.{}/.json'.format(name, FBRTDB_URL))

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_fbrtdb_response,
                        threads=threads,
                        redir=False)

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
    elif str(reply.status_code)[0] == 5:
        utils.printc("    Google App Engine app with a 50x error: {}\n"
                     .format(reply.url), 'orange')
        settings.results["gcp"]["appspot"]["error"].append(reply.url)
    elif (reply.status_code == 200
          or reply.status_code == 302
          or reply.status_code == 404):
        utils.printc("    Google App Engine app: {}\n"
                     .format(reply.url), 'green')
        settings.results["gcp"]["appspot"]["open"].append(reply.url)

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

def print_functions_response1(reply):
    """
    Parses the HTTP reply the initial Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    if reply.status_code == 404:
        pass
    elif reply.status_code == 302:
        utils.printc("    Contains at least 1 Cloud Function: {}\n"
                     .format(reply.url), 'green')
        HAS_FUNCS.append(reply.url)
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

def print_functions_response2(reply):
    """
    Parses the HTTP reply from the secondary, brute-force Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    if 'accounts.google.com/ServiceLogin' in reply.url:
        pass
    elif reply.status_code == 403 or reply.status_code == 401:
        utils.printc("    Auth required Cloud Function: {}\n"
                     .format(reply.url), 'orange')
        settings.results["gcp"]["function"]["authRequired"].append(reply.url)

    elif reply.status_code == 405:
        utils.printc("    UNAUTHENTICATED Cloud Function (POST-Only): {}\n"
                     .format(reply.url), 'green')
        settings.results["gcp"]["function"]["open"]["post"].append(reply.url)
    elif reply.status_code == 200 or reply.status_code == 404:
        utils.printc("    UNAUTHENTICATED Cloud Function (GET-OK): {}\n"
                     .format(reply.url), 'green')
        settings.results["gcp"]["function"]["open"]["get"].append(reply.url)
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

def check_functions(names, brute_list, quickscan, threads):
    """
    Checks for Google Cloud Functions running on cloudfunctions.net

    This is a two-part process. First, we want to find region/project combos
    that have existing Cloud Functions. The URL for a function looks like this:
    https://[ZONE]-[PROJECT-ID].cloudfunctions.net/[FUNCTION-NAME]

    We look for a 302 in [ZONE]-[PROJECT-ID].cloudfunctions.net. That means
    there are some functions defined in that region. Then, we brute force a list
    of possible function names there.

    See gcp_regions.py to define which regions to check. The tool currently
    defaults to only 1 region, so you should really modify it for best results.
    """
    print("[+] Checking for project/zones with Google Cloud Functions.")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Pull the regions from a config file
    regions = gcp_regions.REGIONS

    print("[*] Testing across {} regions defined in the config file"
          .format(len(regions)))

    for region in regions:
        # Initialize the list of initial URLs to check
        candidates = [region + '-' + name + '.' + FUNC_URL for name in names]

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_functions_response1,
                        threads=threads,
                        redir=False)

    # Retun from function if we have not found any valid combos
    if not HAS_FUNCS:
        utils.stop_timer(start_time)
        return

    # Also bail out if doing a quick scan
    if quickscan:
        return

    # If we did find something, we'll use the brute list. This will allow people
    # to provide a separate fuzzing list if they choose.
    print("[*] Brute-forcing function names in {} project/region combos"
          .format(len(HAS_FUNCS)))

    # Load brute list in memory, based on allowed chars/etc
    brute_strings = utils.get_brute(brute_list)

    # The global was built in a previous function. We only want to brute force
    # project/region combos that we know have existing functions defined
    for func in HAS_FUNCS:
        print("[*] Brute-forcing {} function names in {}"
              .format(len(brute_strings), func))
        # Initialize the list of initial URLs to check. Strip out the HTTP
        # protocol first, as that is handled in the utility
        func = func.replace("http://", "")

        # Noticed weird behaviour with functions when a slash is not appended.
        # Works for some, but not others. However, appending a slash seems to
        # get consistent results. Might need further validation.
        candidates = [func + brute + '/' for brute in brute_strings]

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=False,
                            callback=print_functions_response2,
                            threads=threads)

    # Stop the time
    utils.stop_timer(start_time)

def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    check_gcp_buckets(names, args.threads)
    check_fbrtdb(names, args.threads)
    check_appspot(names, args.threads)
    check_functions(names, args.brute, args.quickscan, args.threads)
