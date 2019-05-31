# cloud_enum
Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.

Currently enumerates:
- Open Amazon S3 Buckets
- Protected Amazon S3 Buckets
- Microsoft Azure Storage Accounts
- Open Microsoft Azure Containers
- Open Google Cloud Platform Buckets

Right now, by "open" buckets/containers, I mean those that allow anonymous users to list contents. if you discover a protected bucket/container, it is still worth trying to brute force the contents with another tool.

# Usage
The only required argument is at least one keyword. This is what will be used to find the names of S3 Buckets, Azure Storage Accounts, and Google Cloud Buckets. This keyword will be mutated by prepending and then appending the strings in `cloudenum/mutations.txt`.

You can provide multiple keywords by specifying the `-k` argument multiple times.

Azure Containers required two levels of brute-forcing, both handled automatically by this tool. First, by finding valid accounts. Then, by brute-forcing the name of containers inside that account. That second layer of discovery will use the strings in the `cloud_enum/brute.txt` file.

Alternatively, you can specify your own mutation and brute files.

Let's say you were researching "somecompany" whose website is "somecompany.io" that makes a product called "blockchaindoohickey". You could run the tool like this:

```sh
cloudenum.py -k somecompany -k somecompany.io -k blockchaindoohickey
```

**Complete Usage Details**
```
usage: cloud_enum.py [-h] -k KEYWORD [-m MUTATIONS] [-b BRUTE]

Multi-cloud enumeration utility. All hail OSINT!

optional arguments:
  -h, --help            show this help message and exit
  -k KEYWORD, --keyword KEYWORD
                        Keyword. Can use argument multiple times.
  -m MUTATIONS, --mutations MUTATIONS
                        Mutations. Default: cloud_enum/mutations.txt.
  -b BRUTE, --brute BRUTE
                        List to brute-force Azure container names. Default:
                        cloud_enum/brute.txt.
```

# Roadmap
I plan to implement some more things, like:
- Adding content to `mutations.txt` and `brute.txt` - they are most POC-length right now.
- Searching for test virtual machine instances (which often have unfinished, vulnerable web apps)
- Adding additional public resources, where it makes sense
- Threading for performance (considering requests-futures or Twisted)

<img src="screenshot.png" align="center"/>
