"""
Helper functions for network requests, etc
"""

import time
import sys
import subprocess
try:
    from concurrent.futures import ThreadPoolExecutor
    from requests_futures.sessions import FuturesSession
except ImportError:
    print("[!] You'll need to pip install requests-futures for this tool.")
    sys.exit()


def get_url_batch(url_list, use_ssl=False, callback='', threads=5):
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

    # Start a requests object
    session = FuturesSession(executor=ThreadPoolExecutor(max_workers=threads))

    # Using the async requests-futures module, work in batches based on
    # the 'queue' list created above. Call each URL, sending the results
    # back to the callback function.
    for batch in queue:
        batch_pending = {}
        batch_results = {}

        # First, grab the pending async request and store it in a dict
        for url in batch:
            try:
                batch_pending[url] = session.get(proto + url)
            except ConnectionResetError:
                print("[!] Connection reset error... Slow down?")

        # Then, grab all the results from the queue
        for url in batch_pending:
            batch_results[url] = batch_pending[url].result()

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

def fast_dns_lookup(names, nameserver, callback='', threads=5):
    """
    Helper function to resolve DNS names.

    This is not actually fast yet. A future improvement should be threading
    and raw socket DNS lookups, as opposed to host system calls.
    """
    total = len(names)
    current = 0
    valid_names = []

    print("[*] Brute-forcing a list of {} possible DNS names".format(total))

    # Break the url list into smaller lists based on thread size
    queue = [names[x:x+threads] for x in range(0, len(names), threads)]

    # Work through the smaller lists in batches. Using Python's subprocess
    # module, those host OS will execute the `host` command. Python will
    # move on to the next and then check the output of the OS command when
    # finished queueing the batch. A status code of 0 means the host lookup
    # succeeded.
    for batch in queue:
        batch_pending = {}
        batch_results = {}

        # First, grab the pending async request and store it in a dict
        for name in batch:
            # Build the OS command to lookup a DNS name
            cmd = ['host', '{}'.format(name), '{}'.format(nameserver)]

            # Run the command and store the pending output
            batch_pending[name] = subprocess.Popen(cmd,
                                                   stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL)

        # Then, grab all the results from the queue
        for name in batch_pending:
            batch_pending[name].wait()
            batch_results[name] = batch_pending[name].poll()

            # If we get a 0, save it as a valid DNS name and send to callback
            # if defined.
            if batch_results[name] == 0:
                valid_names.append(name)
                if callback:
                    callback(name)

        # Refresh a status message
        current += threads
        sys.stdout.flush()
        sys.stdout.write("    {}/{} complete...".format(current, total))
        sys.stdout.write('\r')

    # Clear the status message
    sys.stdout.write('                            \r')

    # Return the list of valid dns names
    return valid_names

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
    printc("    DONE", 'black')
    print(" Elapsed time: {}".format(formatted_time))
    print("")
