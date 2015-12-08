import sys
import argparse
import json
from time import sleep
from operator import itemgetter
try:
    import requests
    from cymon import Cymon
    from bs4 import BeautifulSoup
except ImportError:
    print('''Some required modules is not found.
          Please install them with:
          pip install requests
          pip install cymon
          pip install beautifulsoup4''')
    sys.exit(1)

VERSION = "1.0"
CYMON_API = ""
VT_API = ""
UA = {"User-Agent": "Harbinger Threat Intelligence/%s" % VERSION}


def read_file(filename):
    with open(filename) as f:
        for line in f:
            yield line.strip("\n")


def get_data(url, data):
    try:
        r = requests.get(url + data, headers=UA)
        if r.status_code == 200:
            html_page = r.text
            return html_page
        else:
            print("Request was unsuccessful. Status code: %s" % r.status_code)
            return
    except requests.exceptions.HTTPError as e:
        print("Error: %s" % e)
        return


def ipvoid(html_page):
    try:
        soup = BeautifulSoup(html_page, "html.parser")
        data = soup.find("table")
        if data:
            blacklist_data = data.find("td", text="Blacklist Status")
            blacklist_results = blacklist_data.findNext("td").text
            last_analysis_data = data.find("td", text="Analysis Date")
            last_analysis_results = last_analysis_data.findNext("td").text
            ip_addr_data = data.find("td", text="IP Address")
            ip_addr_results = ip_addr_data.findNext("td").strong.text
            rdns_data = data.find("td", text="Reverse DNS")
            rdns_results = rdns_data.findNext("td").text
            asn_data = data.find("td", text="ASN")
            asn_results = asn_data.findNext("td").text
            asn_owner_data = data.find("td", text="ASN Owner")
            asn_owner_results = asn_owner_data.findNext("td").text.replace("&quot;", "")
            country_data = data.find("td", text="Country Code")
            country_results = country_data.findNext("td").text
            return blacklist_results, last_analysis_results, ip_addr_results, rdns_results, asn_results, asn_owner_results, country_results
        else:
            print("Not found on ipvoid")
    except AttributeError as e:
        print("Error parsing ipvoid: %s" % e)
        return


def cymon(api=None, ip=None, domain=None):
    try:
        if api:
            cymon = Cymon(api)
        else:
            cymon = Cymon()
        if ip:
            ip_results = cymon.ip_lookup(ip)
            return ip_results
        elif domain:
            domain_results = cymon.domain_lookup(domain)
            return domain_results
    except requests.exceptions.HTTPError as e:
            print("Error or not found, Cymon says: %s" % e)
            return


def urlvoid(html_page):
    try:
        soup = BeautifulSoup(html_page, "html.parser")
        data = soup.find("table")
        if data:
            safety_data = data.find("td", text="Safety Reputation")
            safety_results = safety_data.findNext("td").text
            last_analysis_data = data.find("td", text="Analysis Date")
            last_analysis_results = last_analysis_data.findNext("td").text
            domain_age_data = data.find("td", text="Domain 1st Registered")
            domain_age_results = domain_age_data.findNext("td").text
            country_data = data.find("td", text="Server Location")
            country_results = country_data.findNext("td").text
            alexa_data = data.find("td", text="Alexa Traffic Rank")
            alexa_results = alexa_data.findNext("td").text
            data_for_ip = soup.find("div", id="ipaddress")
            ipdata = data_for_ip.find("table")
            ip_addr_data = ipdata.find("td", text="IP Address")
            ip_addr_results = ip_addr_data.findNext("td").strong.text
            host_data = ipdata.find("td", text="Hostname")
            host_results = host_data.findNext("td").text
            asn_data = ipdata.find("td", text="ASN")
            asn_results = asn_data.findNext("td").text
            asn_owner_data = ipdata.find("td", text="ASN Owner")
            asn_owner_results = asn_owner_data.findNext("td").text.replace("&quot;", "")
            ip_country_data = ipdata.find("td", text="Country Code")
            ip_country_results = ip_country_data.findNext("td").text
            return safety_results, last_analysis_results, domain_age_results, country_results, alexa_results, ip_addr_results, host_results, asn_results, asn_owner_results, ip_country_results
        else:
            print("Not found on urlvoid")
    except AttributeError as e:
        print("Error parsing urlvoid: %s" % e)
        return


def vt_ip(ip, api):
    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {"ip": ip, "apikey": api}
    r = requests.get(url, params, headers=UA)
    if r.status_code == 204:
        return 204
    if r.status_code == 200:
        data = r.json()
        if data['response_code'] == 1:
            as_owner = data.get('as_owner')
            asn = data.get('asn')
            country = data.get('country')
            if data.get('detected_communicating_samples'):
                detected_comm_samples = len(data.get('detected_communicating_samples'))
            else:
                detected_comm_samples = None
            if data.get('detected_downloaded_samples'):
                detected_down_samples = len(data.get('detected_downloaded_samples'))
            else:
                detected_down_samples = None
            if data.get('detected_referrer_samples'):
                detected_ref_samples = len(data.get('detected_referrer_samples'))
            else:
                detected_ref_samples = None
            if data.get('detected_urls'):
                detected_urls = len(data.get('detected_urls'))
            else:
                detected_urls = None
            if data.get('resolutions'):
                resolutions = data.get('resolutions')
            else:
                resolutions = None
            if data.get('undetected_communicating_samples'):
                undetected_comm_samples = len(data.get('undetected_communicating_samples'))
            else:
                undetected_comm_samples = None
            if data.get('undetected_downloaded_samples'):
                undetected_down_samples = len(data.get('undetected_downloaded_samples'))
            else:
                undetected_down_samples = None
            if data.get('undetected_referrer_samples'):
                undetected_ref_samples = len(data.get('undetected_referrer_samples'))
            else:
                undetected_ref_samples = None
            return as_owner, asn, country, detected_comm_samples, detected_down_samples, detected_ref_samples, detected_urls,\
                resolutions, undetected_comm_samples, undetected_down_samples, undetected_ref_samples
        else:
            print("Request was unsuccessful. Virustotal report: %s" % data['verbose_msg'])
    else:
        print("Something went wrong. VT status code: %s" % r.status_code)


def vt_domain(domain, api):
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {"domain": domain, "apikey": api}
    r = requests.get(url, params, headers=UA)
    if r.status_code == 204:
        return 204
    if r.status_code == 200:
        try:
            data = r.json()
        except json.JSONDecodeError as e:
            print("Json decoding error: %s" % e)
            return
        if data['response_code'] == 1:
            resolutions = data.get('resolutions')
            webutation = data.get('Webutation domain info')
            opera = data.get('Opera domain info')
            if data.get('undetected_referrer_samples'):
                undetected_ref_samples = len(data.get('undetected_referrer_samples'))
            else:
                undetected_ref_samples = None
            wot = data.get('WOT domain info')
            if data.get('detected_downloaded_samples'):
                detected_down_samples = len(data.get('detected_downloaded_samples'))
            else:
                detected_down_samples = None
            if data.get('detected_referrer_samples'):
                detected_ref_samples = len(data.get('detected_referrer_samples'))
            else:
                detected_ref_samples = None
            if data.get('detected_urls'):
                detected_urls = len(data.get('detected_urls'))
            else:
                detected_urls = None
            bitdefender = data.get('BitDefender domain info')
            if data.get('detected_communicating_samples'):
                detected_comm_samples = len(data.get('detected_communicating_samples'))
            else:
                detected_comm_samples = None
            if data.get('undetected_communicating_samples'):
                undetected_comm_samples = len(data.get('undetected_communicating_samples'))
            else:
                undetected_comm_samples = None
            if data.get('undetected_downloaded_samples'):
                undetected_down_samples = len(data.get('undetected_downloaded_samples'))
            else:
                undetected_down_samples = None
            alexa = data.get('Alexa rank')
            whois = data.get('whois')
            subdomains = data.get('subdomains')
            return resolutions, webutation, opera, undetected_ref_samples, wot, detected_down_samples, detected_ref_samples,\
                       detected_urls, bitdefender, detected_comm_samples, undetected_comm_samples, undetected_down_samples, alexa, whois, subdomains
        else:
            print("Request was unsuccessful. Virustotal report: %s" % data['verbose_msg'])
    else:
        print("Something went wrong, VT status code: %s" % r.status_code)


def vt_hash(h, api):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"resource": h, "apikey": api}
    r = requests.get(url, params, headers=UA)
    if r.status_code == 204:
        return 204
    if r.status_code == 200:
        data = r.json()
        if data['response_code'] == 1:
            scan_date = data['scan_date']
            results = str(data['positives']) + "/" + str(data['total'])
            details = data['scans']
            return scan_date, results, details
        else:
            print("Request was unsuccessful. Virustotal report: %s" % data['verbose_msg'])
    else:
        print("Something went wrong, VT status code: %s" % r.status_code)


def vt_url(domain, api):
    if domain:
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {"resource": "http://" + domain, "apikey": api}
        r = requests.get(url, params, headers=UA)
        if r.status_code == 204:
            return 204
        if r.status_code == 200:
            try:
                data = r.json()
            except json.JSONDecodeError as e:
                print("Json decoding error %s" % e)
                return
            if data['response_code'] == 1:
                scan_date = data['scan_date']
                results = str(data['positives']) + "/" + str(data['total'])
                return scan_date, results
            else:
                print("Request was unsuccesful. Virustotal report: %s" % data['verbose_msg'])
        else:
            print("Something went wrong, VT status code: %s" % r.status_code)


def main():
    parser = argparse.ArgumentParser(description="Domain/IP/Hash threat feeds checker. "
                                                 "Will check ipvoid, urlvoid, virustotal and cymon.")
    parser.add_argument("-i", "--ip", help="ip address to check")
    parser.add_argument("-d", "--domain", help="domain to check")
    parser.add_argument("-a", "--hash", help="hash to check")
    parser.add_argument("-fd", "--file-domain", help="file with domain list to check. One per line.")
    parser.add_argument("-fi", "--file-ip", help="file with ip list to check. One per line.")
    parser.add_argument("-fh", "--file-hash", help="file with hashes(MD5,SHA1,SHA256) to check. One per line.")
    parser.add_argument("--api", help="Optional api key for Cymon")
    parser.add_argument("--vtapi", help="Virustotal api key.")
    args = parser.parse_args()
    if CYMON_API:
        args.api = CYMON_API
    if VT_API:
        args.vtapi = VT_API
    if args.ip:
        if args.api:
            cymon_data = cymon(api=args.api, ip=args.ip)
        else:
            cymon_data = cymon(ip=args.ip)
        data = get_data("http://ipvoid.com/scan/", args.ip)
        ipvoid_results = ipvoid(data)
        if args.vtapi:
            vt_data = vt_ip(args.ip, args.vtapi)
            counter = 0
            while vt_data == 204 and counter < 3:
                print("Virustotal API limit reached. Public API limit is 4 req/per minute."
                      "Sleeping for 30 seconds. Will try 3 attempts.")
                sleep(30)
                vt_data = vt_ip(args.ip, args.vtapi)
                counter += 1
            if vt_data and counter < 3:
                print('''
            Virustotal report for IP %s
            =======================
            AS owner: %s
            ASN: %s
            Location: %s
            How many malicious samples communicated with this IP: %s
            How many malicious samples were downloaded from this IP: %s
            How many malicious samples embed this IP in their strings: %s
            How many malicious URLs hosted by this IP: %s
            How many undetected samples communicated with this IP: %s
            How many undetected samples were downloaded from this IP: %s
            How many undetected samples embed this IP in their strings: %s
                ''' % (args.ip, vt_data[0], vt_data[1], vt_data[2], vt_data[3], vt_data[4], vt_data[5], vt_data[6],
                       vt_data[8], vt_data[9], vt_data[10]))

                try:
                    print('''
                    The following domains resolve to this IP(last 10): ''')
                    sorted_ips = sorted(vt_data[7], key=itemgetter("last_resolved"), reverse=True)
                    for i in sorted_ips[:10]:
                        print('''
                    Domain: %s ''' % i.get("hostname"),
                    '''
                    Last resolved: %s''' % i.get("last_resolved"))
                except TypeError:
                    pass
        if cymon_data:
            print('''
            Cymon report for IP %s
            =======================
            Record created: %s
            Last updated: %s
            Blacklisted by: %s
            ''' % (args.ip, cymon_data.get('created'), cymon_data.get('updated'), cymon_data.get('sources')))
        if ipvoid_results:
            print('''
            ipvoid report for IP %s
            =======================
            Blacklist: %s
            Last time analysed: %s
            Reverse DNS: %s
            ASN: %s
            ASN Owner: %s
            Location: %s
            ''' % (args.ip, ipvoid_results[0], ipvoid_results[1], ipvoid_results[3], ipvoid_results[4], ipvoid_results[5],
                      ipvoid_results[6]))
    elif args.domain:
        if args.api:
            cymon_data = cymon(api=args.api, domain=args.domain)
        else:
            cymon_data = cymon(domain=args.domain)
        data = get_data("http://urlvoid.com/scan/", args.domain)
        if args.vtapi:
            vt_data1 = vt_domain(args.domain, args.vtapi)
            vt_data2 = vt_url(args.domain, args.vtapi)
            counter = 0
            while vt_data1 == 204 or vt_data2 == 204 and counter < 3:
                print("Virustotal API limit reached. Public API limit is 4 req/per minute."
                      "Sleeping for 30 seconds. Will try 3 attempts.")
                sleep(30)
                vt_data1 = vt_domain(args.domain, args.vtapi)
                vt_data2 = vt_url(args.domain, args.vtapi)
                counter += 1
            if vt_data1 and vt_data2 and counter < 3:
                print('''
                Virustotal report for domain %s
                =======================
                Blacklist: %s
                Last time analysed: %s
                Webutation report: %s
                Opera report: %s
                WOT report: %s
                BitDefender report: %s
                Alexa rank: %s
                How many malicious samples communicated with this domain: %s
                How many malicious samples were downloaded from this domain: %s
                How many malicious samples embed this domain in their strings: %s
                How many malicious URLs hosted by this domain: %s
                How many undetected samples communicated with this domain: %s
                How many undetected samples were downloaded from this domain: %s
                How many undetected samples embed this domain in their strings: %s
                Subdomains on this domain:
                %s
                WHOIS:
                ======
                %s
                ''' % (args.domain, vt_data2[1], vt_data2[0], vt_data1[1], vt_data1[2], vt_data1[4], vt_data1[8],
                       vt_data1[12], vt_data1[9], vt_data1[5], vt_data1[6], vt_data1[7], vt_data1[10], vt_data1[11],
                       vt_data1[3], vt_data1[14], vt_data1[13]))

                try:
                    print('''
                    This domain resolves to following IPs(last 10): ''')
                    sorted_ips = sorted(vt_data1[0], key=itemgetter('last_resolved'), reverse=True)
                    for i in sorted_ips[:10]:
                        print('''
                    IP: %s''' % i.get("ip_address"),
                    '''
                    Last resolved: %s''' % i.get("last_resolved"))
                except TypeError:
                    pass
        if data:
            urlvoid_results = urlvoid(data)
            if urlvoid_results:
                print('''
                urlvoid report for domain %s
                =======================
                Blacklist: %s
                Last time analysed: %s
                Domain 1st Registered: %s
                Location: %s
                Alexa Rank: %s
                IP: %s
                Hostname: %s
                ASN: %s
                ASN Owner: %s
                IP Location: %s
                ''' % (args.domain, urlvoid_results[0], urlvoid_results[1], urlvoid_results[2], urlvoid_results[3], urlvoid_results[4],
                          urlvoid_results[5], urlvoid_results[6], urlvoid_results[7], urlvoid_results[8], urlvoid_results[9]))
        if cymon_data:
            print('''
            Cymon report for domain %s
            =======================
            Record created: %s
            Last updated: %s
            Blacklisted by: %s
            ''' % (args.domain, cymon_data.get('created'), cymon_data.get('updated'), cymon_data.get('sources')))
    elif args.hash:
        if args.vtapi:
            vt_data = vt_hash(args.hash, args.vtapi)
            counter = 0
            while vt_data == 204 and counter < 3:
                print("Virustotal API limit reached. Public API limit is 4 req/per minute."
                      "Sleeping for 30 seconds. Will try 3 attempts.")
                sleep(30)
                vt_data = vt_hash(args.hash, args.vtapi)
                counter += 1
            if vt_data and counter < 3:
                print('''
                Virustotal report for hash %s
                =======================
                Detection: %s
                Last time analysed: %s
                ''' % (args.hash, vt_data[1], vt_data[0]))
                print("Analysis details: ")
                for k, v in vt_data[2].items():
                    print('''
                    Antivirus %s version %s
                    ============
                    Result: %s
                    Last Updated: %s
                    Detected: %s
                    ''' % (k, v.get('version'), v.get('result'), v.get('update'), v.get('detected')))
    elif args.file_ip:
        if CYMON_API:
            args.api = CYMON_API
        if VT_API:
            args.vtapi = VT_API
        data = read_file(args.file_ip)
        with open("ips_report.json", 'w') as f:
            results = {"ip": "", "cymon_record_created": "", "cymon_last_updated": "", "cymon_blacklists": "", "cymon_url": "", "ipvoid_blacklists": "",
                          "ipvoid_last_time_analysed": "", "ipvoid_reverse_dns": "", "ipvoid_asn": "", "ipvoid_asn_owner": "",
                       "ipvoid_location": "", "ipvoid_url": "", "vt_asn": "", "vt_asn_owner": "", "vt_location": "",
                       "vt_count_samples_malicious_communicated_with": "", "vt_count_samples_malicious_downloaded_from": "",
                       "vt_count_samples_malicious_embed_this_address": "", "vt_count_malicious_urls_hosted_by": "",
                       "vt_count_samples_undetected_communicated_with": "", "vt_count_samples_undetected_downloaded_from": "",
                       "vt_count_samples_undetected_embed_this_address": "", "vt_last10_dns_resolutions": "", "vt_url": ""}
            for ip in data:
                print("Working on %s" % ip)
                results["ip"] = ip
                if args.api:
                    cymon_data = cymon(api=args.api, ip=ip)
                else:
                    cymon_data = cymon(ip=ip)
                if cymon_data:
                    results["cymon_record_created"] = cymon_data.get('created')
                    results["cymon_last_updated"] = cymon_data.get('updated')
                    results["cymon_blacklists"] = cymon_data.get('sources')
                    results["cymon_url"] = "https://cymon.io/" + ip
                ipvoid_data = get_data("http://ipvoid.com/scan/", ip)
                if ipvoid_data:
                    ipvoid_results = ipvoid(ipvoid_data)
                    if ipvoid_results:
                        results["ipvoid_blacklists"] = ipvoid_results[0].strip("POSSIBLY SAFE").strip("BLACKLISTED")
                        results["ipvoid_last_time_analysed"] = ipvoid_results[1]
                        results["ipvoid_reverse_dns"] = ipvoid_results[3]
                        results["ipvoid_asn"] = ipvoid_results[4]
                        results["ipvoid_asn_owner"] = ipvoid_results[5]
                        results["ipvoid_location"] = ipvoid_results[6]
                        results["ipvoid_url"] = "http://ipvoid.com/scan/" + ip
                if args.vtapi:
                    vt_data = vt_ip(ip, args.vtapi)
                    counter = 0
                    while vt_data == 204 and counter < 3:
                        print("Virustotal API limit reached. Public API limit is 4 req/per minute."
                              "Sleeping for 30 seconds. Will try 3 attempts.")
                        sleep(30)
                        vt_data = vt_ip(ip, args.vtapi)
                        counter += 1
                    if vt_data and counter < 3:
                        last10_ip_resolutions = []
                        if vt_data[7]:
                            sorted_ips = sorted(vt_data[7], key=itemgetter("last_resolved"), reverse=True)
                            for i in sorted_ips[:10]:
                                last10_ip_resolutions.append({"ip_address": i.get("ip_address"), "last_resolved": i.get("last_resolved")})
                        results["vt_asn"] = vt_data[1]
                        results["vt_asn_owner"] = vt_data[0]
                        results["vt_location"] = vt_data[2]
                        results["vt_count_samples_malicious_communicated_with"] = vt_data[3]
                        results["vt_count_samples_malicious_downloaded_from"] = vt_data[4]
                        results["vt_count_samples_malicious_embed_this_address"] = vt_data[5]
                        results["vt_count_malicious_urls_hosted_by"] = vt_data[6]
                        results["vt_count_samples_undetected_communicated_with"] = vt_data[8]
                        results["vt_count_samples_undetected_downloaded_from"] = vt_data[9]
                        results["vt_count_samples_undetected_embed_this_address"] = vt_data[10]
                        if last10_ip_resolutions:
                            results["vt_last10_dns_resolutions"] = last10_ip_resolutions
                        results["vt_url"] = "https://www.virustotal.com/en/ip-address/%s/information/" % ip
                json.dump(results, f, indent=4)
            print("File ips_report.json created")
    elif args.file_domain:
        data = read_file(args.file_domain)
        if CYMON_API:
            args.api = CYMON_API
        if VT_API:
            args.vtapi = VT_API
        with open("domains_report.json", 'w') as f:
            results = {"domain": "", "cymon_record_created": "", "cymon_last_updated": "", "cymon_blacklists": "", "cymon_url": "", "urlvoid_blacklists": "",
                          "urlvoid_last_time_analysed": "", "urlvoid_domain_1st_registration": "", "urlvoid_location": "", "urlvoid_alexa": "",
                       "urlvoid_ip": "", "urlvoid_hostname": "", "urlvoid_asn": "", "urlvoid_asn_owner": "", "urlvoid_ip_location": "", "urlvoid_url": "",
                       "vt_blacklist": "", "vt_last_time_analysed": "", "vt_webutation": "", "vt_opera": "", "vt_wot": "",
                       "vt_bitdefender": "", "vt_alexa": "", "vt_count_samples_malicious_communicated_with": "", "vt_count_samples_malicious_downloaded_from": "",
                       "vt_count_samples_malicious_embed_this_domain": "", "vt_count_malicious_urls_hosted_by": "",
                       "vt_count_samples_undetected_communicated_with": "", "vt_count_samples_undetected_downloaded_from": "",
                       "vt_count_samples_undetected_embed_this_domain": "", "vt_subdomains": "", "vt_whois": "",
                       "vt_last10_ip_resolutions": "", "vt_url": ""}
            for domain in data:
                print("Working on %s" % domain)
                results["domain"] = domain
                if args.api:
                    cymon_data = cymon(api=args.api, domain=domain)
                else:
                    cymon_data = cymon(domain=domain)
                if cymon_data:
                    results["cymon_record_created"] = cymon_data.get('created')
                    results["cymon_last_updated"] = cymon_data.get('updated')
                    results["cymon_blacklists"] = cymon_data.get('sources')
                    results["cymon_url"] = "https://cymon.io/domain/" + domain
                urlvoid_data = get_data("http://urlvoid.com/scan/", domain)
                if urlvoid_data:
                    urlvoid_results = urlvoid(urlvoid_data)
                    if urlvoid_results:
                        results["urlvoid_blacklists"] = urlvoid_results[0]
                        results["urlvoid_last_time_analysed"] = urlvoid_results[1]
                        results["urlvoid_domain_1st_registration"] = urlvoid_results[2]
                        results["urlvoid_location"] = urlvoid_results[3]
                        results["urlvoid_alexa"] = urlvoid_results[4]
                        results["urlvoid_ip"] = urlvoid_results[5]
                        results["urlvoid_hostname"] = urlvoid_results[6]
                        results["urlvoid_asn"] = urlvoid_results[7]
                        results["urlvoid_asn_owner"] = urlvoid_results[8]
                        results["urlvoid_ip_location"] = urlvoid_results[9]
                        results["urlvoid_url"] = "http://urlvoid.com/scan/" + domain
                if args.vtapi:
                    vt_data1 = vt_domain(domain, args.vtapi)
                    vt_data2 = vt_url(domain, args.vtapi)
                    counter = 0
                    while vt_data1 == 204 or vt_data2 == 204 and counter < 3:
                        print("Virustotal API limit reached. Public API limit is 4 req/per minute."
                              "Sleeping for 30 second. Will try 3 attempts.")
                        sleep(30)
                        vt_data1 = vt_domain(domain, args.vtapi)
                        vt_data2 = vt_url(domain, args.vtapi)
                        counter += 1
                    if vt_data1 and vt_data2 and counter < 3:
                        last10_ip_resolutions = []
                        if vt_data1[0]:
                            sorted_ips = sorted(vt_data1[0], key=itemgetter("last_resolved"), reverse=True)
                            for i in sorted_ips[:10]:
                                last10_ip_resolutions.append({"ip_address": i.get("ip_address"), "last_resolved": i.get("last_resolved")})
                        results["vt_blacklist"] = vt_data2[1]
                        results["vt_last_time_analysed"] = vt_data2[0]
                        results["vt_webutation"] = vt_data1[1]
                        results["vt_opera"] = vt_data1[2]
                        results["vt_wot"] = vt_data1[4]
                        results["vt_bitdefender"] = vt_data1[8]
                        results["vt_alexa"] = vt_data1[12]
                        results["vt_count_samples_malicious_communicated_with"] = vt_data1[9]
                        results["vt_count_samples_malicious_downloaded_from"] = vt_data1[5]
                        results["vt_count_samples_malicious_embed_this_address"] = vt_data1[6]
                        results["vt_count_malicious_urls_hosted_by"] = vt_data1[7]
                        results["vt_count_samples_undetected_communicated_with"] = vt_data1[10]
                        results["vt_count_samples_undetected_downloaded_from"] = vt_data1[11]
                        results["vt_count_samples_undetected_embed_this_address"] = vt_data1[3]
                        if last10_ip_resolutions:
                            results["vt_last10_ip_resolutions"] = last10_ip_resolutions
                        results["vt_subdomains"] = vt_data1[14]
                        results["vt_whois"] = vt_data1[13]
                        results["vt_url"] = "https://www.virustotal.com/en/domain/%s/information/" % domain
                json.dump(results, f, indent=4)
            print("File domains_report.json created")
    elif args.file_hash:
        data = read_file(args.file_hash)
        if VT_API:
            args.vtapi = VT_API
        with open("hashes_report.json", "w") as f:
            results = {"hash": "", "vt_detection": "", "vt_last_time_analysed": "", "vt_details": ""}
            for h in data:
                print("Working on %s" % h)
                results["hash"] = h
                if args.vtapi:
                    vt_data = vt_hash(h, args.vtapi)
                    counter = 0
                    while vt_data == 204 and counter < 3:
                        print("Virustotal API limit reached. Public API limit is 4 req/per minute."
                              "Sleeping for 30 seconds. Will try 3 attempts.")
                        sleep(30)
                        vt_data = vt_hash(h, args.vtapi)
                        counter += 1
                        print(counter)
                    if vt_data and counter < 3:
                        results["vt_detection"] = vt_data[1]
                        results["vt_last_time_analysed"] = vt_data[0]
                        results["vt_details"] = vt_data[2]
                json.dump(results, f, indent=4)
            print("File hashes_report.json is created")
    else:
        print('''
  _    _            _     _
 | |  | |          | |   (_)
 | |__| | __ _ _ __| |__  _ _ __   __ _  ___ _ __
 |  __  |/ _` | '__| '_ \| | '_ \ / _` |/ _ \ '__|
 | |  | | (_| | |  | |_) | | | | | (_| |  __/ |
 |_|  |_|\__,_|_|  |_.__/|_|_| |_|\__, |\___|_|
                                   __/ |
                                  |___/
            Threat Intelligence

        ''')
        parser.print_help()
main()
