# Unified IP Threat DB Generator

This project automatically compiles and merges open-source network intelligence data. 

The IP address data is pieced together from different open-source repos published by [OXL](https://risk.oxl.app), and is used to generate an `mmdb` containing IP, ASN, type and threat mapping.

## Usage

`pip install -r requirements.txt `

`python build_db.py`

## Disclaimer

Note that this is intended to be a **proof-of-concept only**. The code isn't anywhere close to production-grade^, we focus only on IPv4 addresses, we're using Python packages that haven't been updated in a while, and the source databases that the code relies on might not be updated frequently. Therefore, data produced by this tool might not be entirely accurate. In a production environment, commercial services such as [MaxMind](https://www.maxmind.com/en/home) and [IPinfo](https://ipinfo.io/) can be used instead.

> [!NOTE] ^
> Strangely enough, when using a supposedly more optimised version of the code, MMDB writes consistently failed due to OOM. 

Note also that in the event of a single IP range mapping to more than one ASN, we use the last value in the dataset. This gives rise to inaccuracies that we accept for the purpose of a PoC, but which should be better handled in production.