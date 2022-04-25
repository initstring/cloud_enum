"""
Cloud Checker will contain classes to be re-used in each cloud provider.

The intent is to have a common foundation that can be used for all checks.
"""

from enum import Enum
import requests


class AccessLevel(Enum):
    """
    The access level reports how accessible a finding is
    """
    PUBLIC = 1
    PROTECTED = 2
    DISABLED = 3


class Checker:
    """
    Contains the base functionality used by both HTTPChecker and DNSChecker
    """
    def __init__(self, threads=5):
        self.threads = threads
        self.targets = set()
        self.sigs = []

    def add_targets(self, targets):
        """
        Targets should be a list of strings in full URL format.
        """
        if not isinstance(targets, list):
            raise TypeError("Must be a list")
        self.targets.update(targets)

    def add_sig(self, raw_sig):
        """
        Adds a definition of a finding.

        This consists of the following:
        finding: text describing the finding (string)
        access: enum of AccessLevel (1, 2, 3) that can be used to assess
                severity
        resp_code: for HTTP scraping, the response code (int)
        resp_text: for HTTP scraping, the response text (string)
        dns: for DNS scraping, set to True (bool)

        There might be multiple signatures for a single type of target. For
        example, a GCP bucket would have a signature with a resp code of 200
        for open buckets and 403 for a protected bucket.
        """
        new_sig = dict(
            finding=raw_sig.get("finding", None),
            access=raw_sig.get("access", None),
            resp_code=raw_sig.get("resp_code", None),
            resp_text=raw_sig.get("resp_text", None),
            dns=raw_sig.get("dns", False)
        )

        # A signature must have at least an HTTP response code or a DNS check
        if not new_sig["dns"] and not new_sig["resp_code"]:
            raise ValueError("Must have at least resp_code or dns")

        # Type check everything
        if not isinstance(new_sig["resp_code"], (int, type(None))):
            raise TypeError("Must be a string")
        if not isinstance(new_sig["finding"], (str, type(None))):
            raise TypeError("Must be a string")
        if not isinstance(new_sig["access"], (AccessLevel, type(None))):
            raise TypeError("Must be an AccessLevel enum")
        if not isinstance(new_sig["resp_text"], (str, type(None))):
            raise TypeError("Must be a string")
        if not isinstance(new_sig["dns"], (str, bool)):
            raise TypeError("Must be a bool")

        self.sigs.append(new_sig)


class HTTPChecker(Checker):
    """
    Used to perform simple web-scraping, analyzing the results based on
    known pattern matches of HTTP response codes and text.
    """

    @staticmethod
    def check_target(target, sig):
        """
        Checks an individual target for a pattern match.

        Returns True/False based on the HTTP response and the provided
        signature.
        """
        try:
            resp = requests.get(target)
        except requests.exceptions.ConnectionError as error_msg:
            print(f"    [!] Connection error on {target}:")
            print(error_msg)
            return False
        except TimeoutError:
            print(f"    [!] Timeout on {target}.")
            return False

        if resp.status_code == sig["resp_code"]:
            if not sig["resp_text"]:
                # Simple checks match only the response status code
                return True
            if sig["resp_text"] in resp.text:
                # Some checks also require matching response text
                return True

        return False


class DNSChecker(Checker):
    """
    Used to perform simple DNS brute-forcing, analyzing the results based on
    expected query results
    """
