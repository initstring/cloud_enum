"""
Manage JSON output.
"""

JSON_RESULT = {
    "aws" : {
        "s3" : {
            "open" : [],
            "protected" : []
        },
        "apps" : []
    },
    "azure" : {
        "websites" : [],
        "databases" : [],
        "vms" : [],
        "containers" : []
    },
    "gcp" : {
        "bucket": {
            "open" : [],
            "protected" : []
        },
        "firebase":{
            "open" : [],
            "protected" : [],
            "payment" : [],
            "disabled" : []
        },
        "appspot":{
            "open" : [],
            "error" : []
        },
        "function":{
            "viewed" : [],
            "authRequired" : [],
            "open" : {
                "get" : [],
                "post" : []
            }
        }
    }
}