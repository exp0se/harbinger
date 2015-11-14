# Harbinger Threat Intelligence
Domain/IP/Hash threat feeds checker. Will check http://ipvoid.com, http://urlvoid.com, https://cymon.io and https://virustotal.com

Install required packages with
```
pip install -r requirements.txt
```

You can put API keys inside a script.

Results will be saved as json files for file analysis mode or printed on screen for single item.

# Usage
```
  _    _            _     _
 | |  | |          | |   (_)
 | |__| | __ _ _ __| |__  _ _ __   __ _  ___ _ __
 |  __  |/ _` | '__| '_ \| | '_ \ / _` |/ _ \ '__|
 | |  | | (_| | |  | |_) | | | | | (_| |  __/ |
 |_|  |_|\__,_|_|  |_.__/|_|_| |_|\__, |\___|_|
                                   __/ |
                                  |___/
            Threat Intelligence

        
usage: harbinger.py [-h] [-i IP] [-d DOMAIN] [-a HASH] [-fd FILE_DOMAIN]
                    [-fi FILE_IP] [-fh FILE_HASH] [--api API] [--vtapi VTAPI]

Domain/IP/Hash threat feeds checker. Will check ipvoid, urlvoid, virustotal
and cymon.

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        ip address to check
  -d DOMAIN, --domain DOMAIN
                        domain to check
  -a HASH, --hash HASH  hash to check
  -fd FILE_DOMAIN, --file-domain FILE_DOMAIN
                        file with domain list to check. One per line.
  -fi FILE_IP, --file-ip FILE_IP
                        file with ip list to check. One per line.
  -fh FILE_HASH, --file-hash FILE_HASH
                        file with hashes(MD5,SHA1,SHA256) to check. One per
                        line.
  --api API             Optional api key for Cymon
  --vtapi VTAPI         Virustotal api key.
```

