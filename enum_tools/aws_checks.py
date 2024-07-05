"""
AWS-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils
from logger import logger

# Known S3 domain names
S3_URL = 's3.amazonaws.com'
APPS_URL = 'awsapps.com'

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


class AWSChecks:
    def __init__(self, log: logger.Logger, args, names):
        self.log = log
        self.args = args
        self.names = names

    def print_s3_response(self, reply):
        """
        Parses the HTTP reply of a brute-force attempt

        This function is passed into the class object so we can view results
        in real-time.
        """
        data = {'platform': 'aws', 'target': '', 'access': '', 'key': ''}

        if reply.status_code == 404:
            pass
        elif 'Bad Request' in reply.reason:
            pass
        elif reply.status_code == 200:
            data['key'] = 'bucket_open'
            data['target'] = reply.url
            data['access'] = 'public'
            self.log.new().extra(map=data).info('OPEN S3 BUCKET')
            utils.list_bucket_contents(self.log, reply.url)
        elif reply.status_code == 403:
            data['key'] = 'bucket_protected'
            data['target'] = reply.url
            data['access'] = 'protected'
            self.log.new().extra(map=data).info('Protected S3 Bucket')
        elif 'Slow Down' in reply.reason:
            self.log.new().warning("Rate limited by AWS")
            return 'breakout'
        else:
            self.log.new().extra("status_code", reply.status_code).extra(
                "reason", reply.reason).warning(f"Unknown status code from: {reply.url}")

        return None

    def check_s3_buckets(self):
        """
        Checks for open and restricted Amazon S3 buckets
        """
        self.log.new().trace("Checking for S3 buckets")

        # Start a counter to report on elapsed time
        start_time = utils.start_timer()

        # Initialize the list of correctly formatted urls
        candidates = []

        # Take each mutated keyword craft a url with the correct format
        for name in self.names:
            candidates.append(f'{name}.{S3_URL}')

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(self.log, candidates, use_ssl=False,
                            callback=self.print_s3_response,
                            threads=self.args.threads)

        # Stop the time
        self.log.new().trace(
            f"Checking for S3 buckets took {utils.stop_timer(start_time)}")

    def check_awsapps(self):
        """
        Checks for existence of AWS Apps
        (ie. WorkDocs, WorkMail, Connect, etc.)
        """
        data = {'platform': 'aws', 'target': '', 'access': '', 'key': ''}

        self.log.new().trace("Checking for AWS Apps")

        # Start a counter to report on elapsed time
        start_time = utils.start_timer()

        # Initialize the list of domain names to look up
        candidates = []

        # Initialize the list of valid hostnames
        valid_names = []

        # Take each mutated keyword craft a domain name to lookup.
        for name in self.names:
            candidates.append(f'{name}.{APPS_URL}')

        # AWS Apps use DNS sub-domains. First, see which are valid.
        valid_names = utils.fast_dns_lookup(
            self.log, candidates, self.args.nameserver, self.args.nameserverfile, threads=self.args.threads)

        for name in valid_names:
            data['key'] = 'aws_app'
            data['target'] = f'https://{name}'
            data['access'] = 'protected'
            self.log.new().extra(map=data).info('AWS App Found')

        # Stop the timer
        self.log.new().trace(
            f"Checking for AWS Apps took {utils.stop_timer(start_time)}")

    def run_all(self):
        """
        Function is called by main program
        """

        # Use user-supplied AWS region if provided
        # if not regions:
        #    regions = AWS_REGIONS
        self.check_s3_buckets()
        self.check_awsapps()
