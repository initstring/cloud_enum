import pytest

import enum_tools.utils

test_get_url_batch_findings = []
def report_findings(reply):
    if reply.status_code == 404:
        pass
    elif 'Bad Request' in reply.reason:
        pass
    elif reply.status_code == 200:
        test_get_url_batch_findings.append(reply.url)
    elif reply.status_code == 403:
        test_get_url_batch_findings.append(reply.url)

    return None

def test_get_url_batch():
    url_list = ['prod-billing-documents.s3.amazonaws.com/foobar']
    enum_tools.utils.get_url_batch(url_list, callback=report_findings, use_ssl=True)

    if len(test_get_url_batch_findings) == 0:
        msg = f"{url_list=} should have been found"
        pytest.fail(msg)
