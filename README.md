# cloud_enum
Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.

Currently enumerates the following:

**Amazon Web Services**:
- Open / Protected S3 Buckets
- awsapps (WorkMail, WorkDocs, Connect, etc.)

**Microsoft Azure**:
- Storage Accounts
- Open Blob Storage Containers
- Hosted Databases
- Virtual Machines
- Web Apps

**Google Cloud Platform**
- Open / Protected GCP Buckets
- Open / Protected Firebase Realtime Databases
- Google App Engine sites
- Cloud Functions (enumerates project/regions with existing functions, then brute forces actual function names)

See it in action in [Codingo](https://github.com/codingo)'s video demo [here](https://www.youtube.com/embed/pTUDJhWJ1m0).

<img src="https://initstring.keybase.pub/host/images/cloud_enum.png" align="center"/>


# Usage

## Setup
Several non-standard libaries are required to support threaded HTTP requests and dns lookups. You'll need to install the requirements as follows:

```sh
pip3 install -r ./requirements.txt
```

## Running
The only required argument is at least one keyword. You can use the built-in fuzzing strings, but you will get better results if you supply your own with `-m` and/or `-b`.

You can provide multiple keywords by specifying the `-k` argument multiple times.

Keywords are mutated automatically using strings from `enum_tools/fuzz.txt` or a file you provide with the `-m` flag. Services that require a second-level of brute forcing (Azure Containers and GCP Functions) will also use `fuzz.txt` by default or a file you provide with the `-b` flag.

Let's say you were researching "somecompany" whose website is "somecompany.io" that makes a product called "blockchaindoohickey". You could run the tool like this:

```sh
./cloud_enum.py -k somecompany -k somecompany.io -k blockchaindoohickey
```

HTTP scraping and DNS lookups use 5 threads each by default. You can try increasing this, but eventually the cloud providers will rate limit you. Here is an example to increase to 10.

```sh
./cloud_enum.py -k keyword -t 10
```

**IMPORTANT**: Some resources (Azure Containers, GCP Functions) are discovered per-region. To save time scanning, there is a "REGIONS" variable defined in `cloudenum/azure_regions.py and cloudenum/gcp_regions.py` that is set by default to use only 1 region. You may want to look at these files and edit them to be relevant to your own work.

**Complete Usage Details**
```
usage: cloud_enum.py [-h] -k KEYWORD [-m MUTATIONS] [-b BRUTE]

Multi-cloud enumeration utility. All hail OSINT!

optional arguments:
  -h, --help            show this help message and exit
  -k KEYWORD, --keyword KEYWORD
                        Keyword. Can use argument multiple times.
  -kf KEYFILE, --keyfile KEYFILE
                        Input file with a single keyword per line.
  -m MUTATIONS, --mutations MUTATIONS
                        Mutations. Default: enum_tools/fuzz.txt
  -b BRUTE, --brute BRUTE
                        List to brute-force Azure container names. Default: enum_tools/fuzz.txt
  -t THREADS, --threads THREADS
                        Threads for HTTP brute-force. Default = 5
  -ns NAMESERVER, --nameserver NAMESERVER
                        DNS server to use in brute-force.
  -l LOGFILE, --logfile LOGFILE
                        Will APPEND found items to specified file.
  -f FORMAT, --format FORMAT
                        Format for log file (text,json,csv - defaults to text)
  --disable-aws         Disable Amazon checks.
  --disable-azure       Disable Azure checks.
  --disable-gcp         Disable Google checks.
  -qs, --quickscan      Disable all mutations and second-level scans
```

# Thanks
So far, I have borrowed from:
- Some of the permutations from [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/permutations.txt)
