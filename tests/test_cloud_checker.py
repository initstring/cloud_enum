import pytest
from cloud_enum import gcp_sigs
from cloud_enum import cloud_checkers


class TestAddTargets:
    def test_add_targets(self):
        checker = cloud_checkers.HTTPChecker()
        targets = [
            "http://google.com", "https://google.com", "https://google2.com",
            "http://google.com"]
        checker.add_targets(targets)
        assert len(checker.targets) == 3

    def test_add_targets_exceptions(self):
        # Check for bad finding value
        with pytest.raises(TypeError):
            checker = cloud_checkers.HTTPChecker()
            checker.add_targets("this is not a list")


class TestAddSig:
    def test_add_open_bucket_sig(self):
        checker = cloud_checkers.HTTPChecker()

        checker.add_sig(gcp_sigs.gcp_open_bucket)

        found = False

        for sig in checker.sigs:
            if dict(
                finding="Open GCP Bucket",
                access=cloud_checkers.AccessLevel(1),
                resp_code=200,
                resp_text=None,
                dns=False
            ) == sig:
                found = True

        assert found

    def test_add_protected_bucket_sig(self):
        checker = cloud_checkers.HTTPChecker()

        checker.add_sig(gcp_sigs.gcp_protected_bucket)

        found = False

        for sig in checker.sigs:
            if dict(
                finding="Protected GCP Bucket",
                access=cloud_checkers.AccessLevel(2),
                resp_code=403,
                resp_text=None,
                dns=False
            ) == sig:
                found = True

        assert found

    def test_add_dns_sig(self):
        checker = cloud_checkers.DNSChecker()

        checker.add_sig(dict(dns=True))

        found = False

        for sig in checker.sigs:
            if dict(
                finding=None,
                access=None,
                resp_code=None,
                resp_text=None,
                dns=True
            ) == sig:
                found = True

        assert found

    def test_add_sig_exceptions(self):
        # Check for sig that doesn't have either dns or resp_code
        with pytest.raises(ValueError):
            checker = cloud_checkers.HTTPChecker()
            checker.add_sig(dict(resp_text="you need more than this"))
        # Check for bad response code
        with pytest.raises(TypeError):
            checker = cloud_checkers.HTTPChecker()
            checker.add_sig(dict(resp_code="nada"))
        # Check for bad finding value
        with pytest.raises(TypeError):
            checker = cloud_checkers.HTTPChecker()
            checker.add_sig(dict(finding=42, resp_code=200))
        # Check for bad access value
        with pytest.raises(TypeError):
            checker = cloud_checkers.HTTPChecker()
            checker.add_sig(dict(access=42, resp_code=200))
        # Check for bad resp_text value
        with pytest.raises(TypeError):
            checker = cloud_checkers.HTTPChecker()
            checker.add_sig(dict(resp_text=42, resp_code=200))
        # Check for bad dns value
        with pytest.raises(TypeError):
            checker = cloud_checkers.DNSChecker()
            checker.add_sig(dict(dns=42, resp_code=200))


class TestCheckTarget:
    def test_check_target_gcp_bucket(self):
        open_bucket = "https://google.com"
        protected_bucket = "https://known-closed-bucket"
        not_a_bucket = "https://notbucket"

        checker = cloud_checkers.HTTPChecker()
        checker.add_sig(gcp_sigs.gcp_open_bucket)

        assert checker.check_target(open_bucket, checker.sigs[0])
        assert not checker.check_target(protected_bucket, checker.sigs[0])
        assert not checker.check_target(not_a_bucket, checker.sigs[0])
