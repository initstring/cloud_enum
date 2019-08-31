"""
AWS-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils

BANNER = '''
++++++++++++++++++++++++++
      amazon checks
++++++++++++++++++++++++++
'''

# Known S3 domain names
S3_URL = 's3.amazonaws.com'

# Known AWS region names. This global will be used unless the user passes
# in a specific region name. (NOT YET IMPLEMENTED)
AWS_REGIONS = ['amazonaws.com',
               'ap-east-1.amazonaws.com',
               'us-east-2.amazonaws.com',
               'us-west-1.amazonaws.com',
               'us-west-2.amazonaws.com',
               'ap-south-1.amazonaws.com',
               'ap-northeast-1.amazonaws.com',
               'ap-northeast-2.amazonaws.com',
               'ap-northeast-3.amazonaws.com',
               'ap-southeast-1.amazonaws.com',
               'ap-southeast-2.amazonaws.com',
               'ca-central-1.amazonaws.com',
               'cn-north-1.amazonaws.com.cn',
               'cn-northwest-1.amazonaws.com.cn',
               'eu-central-1.amazonaws.com',
               'eu-west-1.amazonaws.com',
               'eu-west-2.amazonaws.com',
               'eu-west-3.amazonaws.com',
               'eu-north-1.amazonaws.com',
               'sa-east-1.amazonaws.com']

def print_s3_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        utils.printc("    OPEN S3 BUCKET: {}\n"
                     .format(reply.url), 'green')
        utils.list_bucket_contents(reply.url)
    elif reply.status_code == 403:
        utils.printc("    Protected S3 Bucket: {}\n"
                     .format(reply.url), 'orange')
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        print("    Unknown status codes being received from {}:\n"
              "       {}: {}"
              .format(reply.url, reply.status_code, reply.reason))

def check_s3_buckets(names, threads):
    """
    Checks for open and restricted Amazon S3 buckets
    """
    print("[+] Checking for S3 buckets")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        candidates.append('{}.{}'.format(name, S3_URL))

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_s3_response,
                        threads=threads)

    # Stop the time
    utils.stop_timer(start_time)

def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    # Use user-supplied AWS region if provided
    #if not regions:
    #    regions = AWS_REGIONS
    check_s3_buckets(names, args.threads)
    return ''
