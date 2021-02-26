# IOC Enricher - Enrich & Relate

### Table of contents

  

------------

- [Introduction](#Introduction)
- [Usage](#Usage)
- Enrich
- Get Relations
- [Contributing](#Contributing)
- [Credits](#Credits)

------------

## Introduction

Enrichment is often one of the most important items on a defenders checklist. To successfully enrich and identify if an IP is malicious or not an analyst often needs to do 2 things.

  

1. Need to check if the indicator is malicious or not by checking it against numerous 'enrichment' sources.

2. Need to go a step further by finding associated IPs/ URLs or hashes to decide if the indicator at hand may be malicious by relation.

  

This tool does exactly that. By using this tool you can automatically enrich indicators against industry leading enrichment sources. With this, you can also search and receive possible relations to an indicator.

Note: Some scripts need API keys to run successfully. Fill in the config.py file to use the script at full capacity

## Usage

### Enrichment

To enrich an IP address, first fill in the API keys needed in the config.py file. After this launch the program via, 'python3 main.py'.

  

Once you launch the program, enter 1 to enrich your IP address against multiple enrichment sources.

  

### Get Relations

To get relations of a particular indicator, launch the program via 'python3 main.py'

  

After launching it enter 2 to get IP relations. Then enter the IP address to get relations!

  

## Contributing

  

We are constantly on the lookout for newer services/ tools to add to our repo. If you would like to contribute the easiest way to do so would be to open an issue and suggest the tool you would like.

  

You can also pull this repo, add your connector and submit a merge request for adding your code directly in our repo!

  

## Credits

Alienvault OTX

Virus Total

Threat Miner

Under Attack

AbuseIPDB

ThreatCrowd
