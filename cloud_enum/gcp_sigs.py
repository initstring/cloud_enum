"""
This module contains only variable names that define GCP-related signatures
"""

from cloud_enum import cloud_checkers


gcp_open_bucket = dict(
    finding="Open GCP Bucket",
    access=cloud_checkers.AccessLevel(1),
    resp_code=200
    )

gcp_protected_bucket = dict(
    finding="Protected GCP Bucket",
    access=cloud_checkers.AccessLevel(2),
    resp_code=403
    )
