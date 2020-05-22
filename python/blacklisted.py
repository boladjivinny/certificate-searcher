import glob
import os
import sys
import ujson

blacklist_dir = sys.argv[1]

from enum import Enum
class Status(Enum):
    ERROR = "ERROR"
    EMPTY = "EMPTY"
    RESPONSE_400 = "4** RESPONSE"
    RESPONSE_500 = "5** RESPONSE"
    PARKED = "PARKED"

class DomainHistory:
    def __init__(self, domain):
        self.dates = {}
        self.domain = domain

    def add_date(self, date, protocol):
        if not date in self.dates:
            self.dates[date] = set()

        self.dates[date].add(protocol)

    def transitioned_to_https(self):
        initially_http_only = False
        for date in sorted(self.dates):
            if len(self.dates[date]) == 1 and 'http' in self.dates[date]:
                initially_http_only = True

            if initially_http_only and 'https' in self.dates[date]:
                return date

        return None

    def transitioned_to_http(self):
        initially_https = False
        for date in sorted(self.dates):
            if 'https' in self.dates[date]:
                initially_https = True

            if initially_https and len(self.dates[date]) == 1 and 'http' in self.dates[date]:
                return date

        return None



def page_classification(jsonData):
    error = jsonData['data']['error'] if 'error' in jsonData['data'] else ""
    if error != "":
        return Status.ERROR

    if len(jsonData['data']['http']) == 0:
        return Status.EMPTY

    http_response = data['data']['http']['response']
    http_status_code = http_response['status_code']
    if 400 <= http_status_code and http_status_code < 500:
        return Status.RESPONSE_400

    if 500 <= http_status_code and http_status_code < 600:
        return Status.RESPONSE_500

    http_body = http_response['body']



protocol_urls = {"http": set(), "https": set()}
protocol_domains = {"http": set(), "https": set()}

domain_histories = {}


for fpath in sorted(glob.glob(os.path.join(blacklist_dir, "*/banners.json")))[0::7]:
    date = fpath.split('/')[-2]
    with open(fpath) as f:
        for line in f:
            if line == "null\n":
                continue

            data = ujson.loads(line.rstrip())
            domain = data['domain']
            url = data['url']
            protocol = url.split(":")[0]

            http_data = data['data']['http']
            error = data['data']['error'] if 'error' in data['data'] else ""
            if error == "" and len(http_data) > 0:
                if not domain in domain_histories:
                    domain_histories[domain] = DomainHistory(domain)

                domain_histories[domain].add_date(date, protocol)

                protocol_urls[protocol].add(":".join(url.split(":")[1:]))
                protocol_domains[protocol].add(domain)

print('-'*40 + "URLS" + '-'*40)
print(f"HTTP: {len(protocol_urls['http'])}")
print(f"HTTPS: {len(protocol_urls['https'])}")
url_intersection = protocol_urls['http'].intersection(protocol_urls['https'])
print(f"HTTPS and HTTP: {len(url_intersection)}")

print('-'*40 + "Domains" + '-'*40)
print(f"HTTP: {len(protocol_domains['http'])}")
print(f"HTTPS: {len(protocol_domains['https'])}")
domain_intersection = protocol_domains['http'].intersection(protocol_domains['https'])
print(f"HTTPS and HTTP: {len(domain_intersection)}")

print('-'*40 + "Domain histories" + '-'*40)
transition_count = 0
for domain, dh in domain_histories.items():
    transition_date = dh.transitioned_to_http()
    if transition_date != None:
        transition_count += 1
        print(f"{domain},{transition_date}")

print(f"{transition_count} transitions from HTTPS to HTTP")
