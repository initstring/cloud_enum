"""
Helper functions for network requests, etc
"""

import time
import sys
import re
import ipaddress
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
from logger import logger
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


def is_valid_domain(domain):
    """
    Checks if the domain has a valid format and length
    """
    # Check for domain total length
    if len(domain) > 253:  # According to DNS specifications
        return False

    # Check each label in the domain
    for label in domain.split('.'):
        # Each label should be between 1 and 63 characters long
        if not (1 <= len(label) <= 63):
            return False

    return True


def get_url_batch(log: logger.Logger, url_list, use_ssl=False, callback='', threads=5, redir=True):
    """
    Processes a list of URLs, sending the results back to the calling
    function in real-time via the `callback` parameter
    """

    # Filter out invalid URLs
    url_list = [url for url in url_list if is_valid_domain(url)]

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
        session = FuturesSession(
            executor=ThreadPoolExecutor(max_workers=threads+5))
        batch_pending = {}
        batch_results = {}

        # First, grab the pending async request and store it in a dict
        for url in batch:
            batch_pending[url] = session.get(
                proto + url, allow_redirects=redir)

        # Then, grab all the results from the queue.
        # This is where we need to catch exceptions that occur with large
        # fuzz lists and dodgy connections.
        for url in batch_pending:
            try:
                # Timeout is set due to observation of some large jobs simply
                # hanging forever with no exception raised.
                batch_results[url] = batch_pending[url].result(timeout=30)
            except requests.exceptions.ConnectionError as error_msg:
                log.new().warning(f"Connection error on {url}: {error_msg}")
            except TimeoutError:
                log.new().warning(
                    f"Timeout on {url}. Investigate if there are many of these")

        # Now, send all the results to the callback function for analysis
        # We need a way to stop processing unnecessary brute-forces, so the
        # callback may tell us to bail out.
        for url in batch_results:
            check = callback(batch_results[url])
            if check == 'breakout':
                return


def read_nameservers(log: logger.Logger, file_path):
    """
    Reads nameservers from a given file.
    Each line in the file should contain one nameserver IP address.
    Lines starting with '#' will be ignored as comments.
    """
    try:
        with open(file_path, 'r') as file:
            nameservers = [line.strip() for line in file if line.strip()
                           and not line.startswith('#')]
        if not nameservers:
            raise ValueError(
                "Nameserver file is empty or only contains comments")
        return nameservers
    except FileNotFoundError:
        log.new().error(f"Error: File '{file_path}' not found.")
        exit(1)
    except ValueError as e:
        log.new().error(e)
        exit(1)


def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def dns_lookup(log: logger.Logger, nameserver, name):
    """
    This function performs the actual DNS lookup when called in a threadpool
    by the fast_dns_lookup function.
    """
    nameserverfile = False
    if not is_valid_ip(nameserver):
        nameserverfile = nameserver

    res = dns.resolver.Resolver()
    res.timeout = 10
    if nameserverfile:
        nameservers = read_nameservers(log, nameserverfile)
        res.nameservers = nameservers
    else:
        res.nameservers = [nameserver]

    try:
        res.query(name)
        # If no exception is thrown, return the valid name
        return name
    except dns.resolver.NXDOMAIN:
        return ''
    except dns.resolver.NoNameservers as exc_text:
        log.new().error(f"Error querying nameservers: {exc_text}")
        return '-#BREAKOUT_DNS_ERROR#-'
    except dns.exception.Timeout:
        log.new().warning(
            f"DNS Timeout on {name}. Investigate if there are many of these")
        return ''


def fast_dns_lookup(log: logger.Logger, names, nameserver, nameserverfile, callback='', threads=5):
    """
    Helper function to resolve DNS names. Uses multithreading.
    """
    valid_names = []

    log.new().trace(
        f"Brute-forcing a list of {len(names)} possible DNS names")

    # Filter out invalid domains
    names = [name for name in names if is_valid_domain(name)]

    # Break the url list into smaller lists based on thread size
    queue = [names[x:x+threads] for x in range(0, len(names), threads)]

    for batch in queue:
        pool = ThreadPool(threads)

        # Because pool.map takes only a single function arg, we need to
        # define this partial so that each iteration uses the same ns
        if nameserverfile:
            dns_lookup_params = partial(dns_lookup, log, nameserverfile)
        else:
            dns_lookup_params = partial(dns_lookup, log, nameserver)

        results = pool.map(dns_lookup_params, batch)

        # We should now have the batch of results back, process them.
        for name in results:
            if name:
                if name == '-#BREAKOUT_DNS_ERROR#-':
                    sys.exit()
                if callback:
                    callback(name)
                valid_names.append(name)
        pool.close()

    return valid_names


def list_bucket_contents(log: logger.Logger, bucket):
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
        for key in keys:
            url = bucket + key
            log.new().extra("bucket", bucket).debug(f"File: {url}")
    else:
        log.new().extra("bucket", bucket).debug("Empty bucket")


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
    Stops timer and returns difference
    """
    # Stop the timer
    elapsed_time = time.time() - start_time
    formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

    return formatted_time
