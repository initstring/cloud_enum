# cloud_enum
Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud. Must be run from a \*nix environment.

Currently enumerates the following:

**Amazon Web Services**:
- Open S3 Buckets
- Protected S3 Buckets

**Microsoft Azure**:
- Storage Accounts
- Open Blob Storage Containers
- Hosted Databases
- Virtual Machines
- Web Apps

**Google Cloud Platform**
- Open GCP Buckets
- Protected GCP Buckets
- Google App Engine sites

By "open" buckets/containers, I mean those that allow anonymous users to list contents. if you discover a protected bucket/container, it is still worth trying to brute force the contents with another tool.

**IMPORTANT**: Azure Virtual Machine DNS records can span a lot of geo regions. To save time scanning, there is a "REGIONS" variable defined in cloudenum/azure_regions.py. You'll want to look at this file and edit it to be relevant to your own work.

<img src="https://initstring.keybase.pub/host/images/cloud_enum.png" align="center"/>


# Usage

## Setup
You'll need the `requests-futures` python package, as this tool uses it for multi-threading HTTP requests. It's a very cool package if you're already using `requests`, I highly recommend it.

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

DNS brute-forcing uses a hard-coded 25 threads, leveraging subprocess and the Linux `host` command.

HTTP scraping uses 5 threads by default. You can try increasing this, but eventually the cloud providers will rate limit you. Here is an example to increase to 10.

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
                        Mutations. Default: cloud_enum/mutations.txt.
  -b BRUTE, --brute BRUTE
                        List to brute-force Azure container names. Default:
                        cloud_enum/brute.txt.
  -t THREADS, --threads THREADS
                        Threads for HTTP brute-force. Default = 5
  -ns NAMESERVER, --nameserver NAMESERVER
                        DNS server to use in brute-force.
  -l LOGFILE, --logfile LOGFILE
                        Will APPEND found items to specified file.
  --disable-aws         Disable Amazon checks.
  --disable-azure       Disable Azure checks.
  --disable-gcp         Disable Google checks.
```

# Thanks
So far, I have borrowed from:
- Some of the permutations from [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/permutations.txt)
