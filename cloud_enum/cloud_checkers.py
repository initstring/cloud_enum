"""
Cloud Checker will contain classes to be re-used in each cloud provider.

The intent is to have a common foundation that can be used for all checks.
"""

from enum import Enum


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

    def add_sig(self, **args):
        """
        Adds a definition of a finding.

        This consists of the following:
        finding: text describing the finding (string)
        access: enum of AccessLevel (1, 2, 3) that can be used to assess
                severity
        resp_code: for HTTP scraping, the response code (int)
        resp_text: for HTTP scraping, the response text (string)
        dns: for DNS scraping, set to True (bool)
        """
        sig = dict(
            finding=args.get("finding", None),
            access=args.get("access", None),
            resp_code=args.get("resp_code", None),
            resp_text=args.get("resp_text", None),
            dns=args.get("dns", False)
        )

        # A signature must have at least an HTTP response code or a DNS check
        if not sig["dns"] and not sig["resp_code"]:
            raise ValueError("Must have at least resp_code or dns")

        # Type check everything
        if not isinstance(sig["resp_code"], (int, type(None))):
            raise TypeError("Must be a string")
        if not isinstance(sig["finding"], (str, type(None))):
            raise TypeError("Must be a string")
        if not isinstance(sig["access"], (AccessLevel, type(None))):
            raise TypeError("Must be an AccessLevel enum")
        if not isinstance(sig["resp_text"], (str, type(None))):
            raise TypeError("Must be a string")
        if not isinstance(sig["dns"], (str, bool)):
            raise TypeError("Must be a bool")

        self.sigs.append(sig)


class HTTPChecker(Checker):
    """
    Used to perform simple web-scraping, analyzing the results based on
    known pattern matches of HTTP response codes and text.
    """

    def check_targets(self):
        """
        This is where the active checks happen
        """


class DNSChecker(Checker):
    """
    Used to perform simple DNS brute-forcing, analyzing the results based on
    expected query results
    """
