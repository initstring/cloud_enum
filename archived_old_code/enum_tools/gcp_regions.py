"""
File used to track the DNS regions for GCP resources.
"""

# Some enumeration tasks will need to go through the complete list of
# possible DNS names for each region. You may want to modify this file to
# use the regions meaningful to you.
#
# Whatever is listed in the last instance of 'REGIONS' below is what the tool
# will use.


# Here is the list I get when running `gcloud functions regions list`
REGIONS = ['us-central1', 'us-east1', 'us-east4', 'us-west2', 'us-west3',
           'us-west4', 'europe-west1', 'europe-west2', 'europe-west3',
           'europe-west6', 'asia-east2', 'asia-northeast1', 'asia-northeast2',
           'asia-northeast3', 'asia-south1', 'asia-southeast2',
           'northamerica-northeast1', 'southamerica-east1',
           'australia-southeast1']


# And here I am limiting the search by overwriting this variable:
REGIONS = ['us-central1', ]
