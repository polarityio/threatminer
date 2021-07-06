# Polarity ThreatMiner Integration

![mode:on demand only](https://img.shields.io/badge/mode-on%20demand%20only-blue.svg)

> As whois lookups return data on nearly every domain, we recommend running this integration in "On-Demand" mode only.

The Polarity - ThreatMiner integration searches ThreatMiner for whois information on domains and IPs as well as sample information related to file hashes.  IMPORTANT NOTE: Please note that the ThreatMiner API rate limit is set to 10 queries per minute.

To learn more about ThreatMiner, please visit the [official website](https://www.threatminer.org/).

Check out the integration in action:

![image](https://user-images.githubusercontent.com/22529325/124612872-aefcac00-de40-11eb-8f2d-c3537a43bdc3.png)

## ThreatMiner Integration Options

### ThreatMiner Api URL
The URL of the ThreatMiner API including the schema (i.e., https://). Default is set to:  https://api.threatminer.org

### Ignore List
List of domains that you never want to send to ThreatMiner.

### Ignore Domain Regex
Domains that match the given regex will not be looked up.

### Ignore IP Regex
IPs that match the given regex will not be looked up.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
