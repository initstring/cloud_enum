"""
Helper functions for network requests, etc
"""

import time
import sys
import datetime
import re
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
try:
    import requests
    import dns
    import dns.resolver
    from concurrent.futures import ThreadPoolExecutor
    from requests_futures.sessions import FuturesSession
    from concurrent.futures._base import TimeoutError
except ImportError:
    print("[!] Please pip install requirements.txt.")
    sys.exit()

LOGFILE = False

def init_logfile(logfile):
    """
    Initialize the global logfile if specified as a user-supplied argument
    """
    if logfile:
        global LOGFILE
        LOGFILE = logfile

        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        with open(logfile, 'a') as log_writer:
            log_writer.write("\n\n#### CLOUD_ENUM {} ####\n"
                             .format(now))

def get_url_batch(url_list, use_ssl=False, callback='', threads=5, redir=True):
    """
    Processes a list of URLs, sending the results back to the calling
    function in real-time via the `callback` parameter
    """

    # Start a counter for a status message
    tick = {}
    tick['total'] = len(url_list)
    tick['current'] = 0

    # Break the url list into smaller lists based on thread size
    queue = [url_list[x:x+threads] for x in range(0, len(url_list), threads)]

    # Define the protocol
    if use_ssl:
        proto = 'https://'
    else:
        proto = 'http://'

    # Using the async requests-futures module, work in batches based on
    # the 'queue' list created above. Call each URL, sending the results
    # back to the callback function.
    for batch in queue:
        # I used to initialize the session object outside of this loop, BUT
        # there were a lot of errors that looked related to pool cleanup not
        # happening. Putting it in here fixes the issue.
        # There is an unresolved discussion here:
        # https://github.com/ross/requests-futures/issues/20
        session = FuturesSession(executor=ThreadPoolExecutor(max_workers=threads+5))
        batch_pending = {}
        batch_results = {}

        # First, grab the pending async request and store it in a dict
        for url in batch:
            batch_pending[url] = session.get(proto + url, allow_redirects=redir)

        # Then, grab all the results from the queue.
        # This is where we need to catch exceptions that occur with large
        # fuzz lists and dodgy connections.
        for url in batch_pending:
            try:
                # Timeout is set due to observation of some large jobs simply
                # hanging forever with no exception raised.
                batch_results[url] = batch_pending[url].result(timeout=30)
            except requests.exceptions.ConnectionError as error_msg:
                print("    [!] Connection error on {}:".format(url))
                print(error_msg)
            except TimeoutError:
                print("    [!] Timeout on {}. Investigate if there are"
                      " many of these".format(url))

        # Now, send all the results to the callback function for analysis
        # We need a way to stop processing unnecessary brute-forces, so the
        # callback may tell us to bail out.
        for url in batch_results:
            check = callback(batch_results[url])
            if check == 'breakout':
                return

        # Refresh a status message
        tick['current'] += threads
        sys.stdout.flush()
        sys.stdout.write("    {}/{} complete..."
                         .format(tick['current'], tick['total']))
        sys.stdout.write('\r')

    # Clear the status message
    sys.stdout.write('                            \r')

def dns_lookup(nameserver, name):
    """
    This function performs the actual DNS lookup when called in a threadpool
    by the fast_dns_lookup function.
    """
    res = dns.resolver.Resolver()
    res.timeout = 10
    res.nameservers = [nameserver]

    try:
        res.query(name)
        # If no exception is thrown, return the valid name
        return name
    except dns.resolver.NXDOMAIN:
        return ''
    except dns.exception.Timeout:
        print("    [!] DNS Timeout on {}. Investigate if there are many"
              " of these.".format(name))

def fast_dns_lookup(names, nameserver, callback='', threads=5):
    """
    Helper function to resolve DNS names. Uses multithreading.
    """
    total = len(names)
    current = 0
    valid_names = []

    print("[*] Brute-forcing a list of {} possible DNS names".format(total))

    # Break the url list into smaller lists based on thread size
    queue = [names[x:x+threads] for x in range(0, len(names), threads)]

    for batch in queue:
        pool = ThreadPool(threads)

        # Because pool.map takes only a single function arg, we need to
        # define this partial so that each iteration uses the same ns
        dns_lookup_params = partial(dns_lookup, nameserver)

        results = pool.map(dns_lookup_params, batch)

        # We should now have the batch of results back, process them.
        for name in results:
            if name:
                if callback:
                    callback(name)
                valid_names.append(name)

        current += threads

        # Update the status message
        sys.stdout.flush()
        sys.stdout.write("    {}/{} complete...".format(current, total))
        sys.stdout.write('\r')
        pool.close()

    # Clear the status message
    sys.stdout.write('                            \r')

    return valid_names

def list_bucket_contents(bucket):
    """
    Provides a list of full URLs to each open bucket
    """
    key_regex = re.compile(r'<(?:Key|Name)>(.*?)</(?:Key|Name)>')
    reply = requests.get(bucket)

    # Make a list of all the relative-path key name
    keys = re.findall(key_regex, reply.text)

    # Need to remove URL parameters before appending file names
    # from Azure buckets
    sub_regex = re.compile(r'(\?.*)')
    bucket = sub_regex.sub('', bucket)

    # Format them to full URLs and print to console
    if keys:
        printc("      FILES:\n", 'none')
        for key in keys:
            url = bucket + key
            printc("      ->{}\n".format(url), 'none')
    else:
        printc("      ...empty bucket, so sad. :(\n", 'none')

def printc(text, color):
    """
    Prints colored text to screen
    """
    # ANSI escape sequences
    green = '\033[92m'
    orange = '\033[33m'
    red = '\033[31m'
    bold = '\033[1m'
    end = '\033[0m'

    if color == 'orange':
        sys.stdout.write(bold + orange + text + end)
    if color == 'green':
        sys.stdout.write(bold + green + text + end)
    if color == 'red':
        sys.stdout.write(bold + red + text + end)
    if color == 'black':
        sys.stdout.write(bold + text + end)
    if color == 'none':
        sys.stdout.write(text)

    if LOGFILE:
        with open(LOGFILE, 'a')  as log_writer:
            log_writer.write(text.lstrip())

def get_brute(brute_file, mini=1, maxi=63, banned='[^a-z0-9_-]'):
    """
    Generates a list of brute-force words based on length and allowed chars
    """
    # Read the brute force file into memory
    with open(brute_file, encoding="utf8", errors="ignore") as infile:
        names = infile.read().splitlines()

    # Clean up the names to usable for containers
    banned_chars = re.compile(banned)
    clean_names = []
    for name in names:
        name = name.lower()
        name = banned_chars.sub('', name)
        if maxi >= len(name) >= mini:
            if name not in clean_names:
                clean_names.append(name)

    return clean_names

def start_timer():
    """
    Starts a timer for functions in main module
    """
    # Start a counter to report on elapsed time
    start_time = time.time()
    return start_time

def stop_timer(start_time):
    """
    Stops timer and prints a status
    """
    # Stop the timer
    elapsed_time = time.time() - start_time
    formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

    # Print some statistics
    print("")
    print(" Elapsed time: {}".format(formatted_time))
    print("")
