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

By "open" buckets/containers, I mean those that allow anonymous users to list contents. if you discover a protected bucket/container, it is still worth trying to brute force the contents with another tool.

**IMPORTANT**: Azure Virtual Machine DNS records can span a lot of geo regions. To save time scanning, there is a "REGIONS" variable defined in cloudenum/azure_regions.py. You'll want to look at this file and edit it to be relevant to your own work.

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

Azure Containers required two levels of brute-forcing, both handled automatically by this tool. First, by finding valid accounts (DNS). Then, by brute-forcing container names inside that account (HTTP scraping). The tool uses the same fuzzing file for both by default, but you can specificy individual files separately if you'd like.

Let's say you were researching "somecompany" whose website is "somecompany.io" that makes a product called "blockchaindoohickey". You could run the tool like this:

```sh
cloudenum.py -k somecompany -k somecompany.io -k blockchaindoohickey
```

HTTP scraping and DNS lookups use 5 threads each by default. You can try increasing this, but eventually the cloud providers will rate limit you. Here is an example to increase to 10.

```sh
cloudenum.py -k keyword -t 10
```

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
                        List to brute-force Azure container names. Default:
                        enum_tools/fuzz.txt
  -t THREADS, --threads THREADS
                        Threads for HTTP brute-force. Default = 5
  -ns NAMESERVER, --nameserver NAMESERVER
                        DNS server to use in brute-force.
  -l LOGFILE, --logfile LOGFILE
                        Will APPEND found items to specified file.
  --disable-aws         Disable Amazon checks.
  --disable-azure       Disable Azure checks.
  --disable-gcp         Disable Google checks.
  -qs, --quickscan      Disable all mutations and second-level scans

```

# Thanks
So far, I have borrowed from:
- Some of the permutations from [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/permutations.txt)
