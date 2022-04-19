"""
Google-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils
from enum_tools import gcp_regions

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
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE BUCKET'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url + '/')
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Bucket'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


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
        candidates.append(f'{GCP_URL}/{name}')

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
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE FIREBASE RTDB'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 401:
        data['msg'] = 'Protected Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 402:
        data['msg'] = 'Payment required on Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif reply.status_code == 423:
        data['msg'] = 'The Firebase database has been deactivated.'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


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
            candidates.append(f'{name}.{FBRTDB_URL}/.json')

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
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif str(reply.status_code)[0] == 5:
        data['msg'] = 'Google App Engine app with a 50x error'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 302, 404):
        if 'accounts.google.com' in reply.url:
            data['msg'] = 'Protected Google App Engine app'
            data['target'] = reply.history[0].url
            data['access'] = 'protected'
            utils.fmt_output(data)
        else:
            data['msg'] = 'Open Google App Engine app'
            data['target'] = reply.url
            data['access'] = 'public'
            utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


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
            candidates.append(f'{name}.{APPSPOT_URL}')

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
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 302:
        data['msg'] = 'Contains at least 1 Cloud Function'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        HAS_FUNCS.append(reply.url)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def print_functions_response2(reply):
    """
    Parses the HTTP reply from the secondary, brute-force Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if 'accounts.google.com/ServiceLogin' in reply.url:
        pass
    elif reply.status_code in (403, 401):
        data['msg'] = 'Auth required Cloud Function'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 405:
        data['msg'] = 'UNAUTHENTICATED Cloud Function (POST-Only)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 404):
        data['msg'] = 'UNAUTHENTICATED Cloud Function (GET-OK)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


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

    print(f"[*] Testing across {len(regions)} regions defined in the config file")

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
    print(f"[*] Brute-forcing function names in {len(HAS_FUNCS)} project/region combos")

    # Load brute list in memory, based on allowed chars/etc
    brute_strings = utils.get_brute(brute_list)

    # The global was built in a previous function. We only want to brute force
    # project/region combos that we know have existing functions defined
    for func in HAS_FUNCS:
        print(f"[*] Brute-forcing {len(brute_strings)} function names in {func}")
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
