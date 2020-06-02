import csv
import glob
import os
import re
import sys
from datetime import datetime

import ujson
from loguru import logger

blacklist_dir = sys.argv[1]
whitelist_fpath = sys.argv[2]

from enum import Enum


class Status(Enum):
    ERROR = "ERROR"
    EMPTY = "EMPTY"
    NO_RESPONSE = "NO HTTP RESPONSE"
    RESPONSE_400 = "4** RESPONSE"
    RESPONSE_500 = "5** RESPONSE"
    PARKED_HTTP = "PARKED HTTP"
    PARKED_DNS = "PARKED DNS"
    NOERROR = "NO ERRORS"


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


parking_strings = [
    'sedoparking.com',
    "parkingcrew.net",
    "snparking.ru",
    'wanwang.aliyun.com/domain/parking',
    "parking services by social8.asia",
    "parkajans.com.t",
    "domainparking.ru",
    "parking.livedns.com",
    "This agreement regarding a domain rental or purchase plan",
    "This domain is currently not approved for CashParking.",
    '"PAGE_ParkingID": ParkingID.toString()',
    "Der Inhaber dieser Domain parkt diese beim Domain-Parking-Programm",
    "These domains for sale are great",
    ".com is for sale !",
    "A GREAT DOMAIN IS ONE OF THE BEST INVESTMENTS YOU CAN MAKE",
    'is for sale.</div>\r\n\t\t\t\t\t<div class="captcha-top-text">Enter the characters below to continue:',
    'Note that if the domain is not currently available for sale it might go on sale soon, so make sure to check frequently',
    "This premium domain name is available for purchase!",
    "Premium Domain Names at already Discounted Prices",
    "This domain name is for sale.",
    "If this is your domain name you must renew it immediately before it is deleted and permanently removed from your account",
    "This domain has expired and is now suspended.",
    "<title>Home - domain expired</title>",
    "<head>\n                <title>Domain Expired</title>\n",
    "Истёк срок регистрации домена",  # Domain is expired
    "This domain name has expired and it is going to be lost.",
    "Click here</a> to renew it.</div>",
    "This Account has been suspended.\n",
    "parked-content.godaddy.com",
]


def page_classification(jsonData, parking_ns):
    if jsonData['domain'] in parking_ns:
        return Status.PARKED_DNS

    error = jsonData['error'] if 'error' in jsonData else ""
    if error != "":
        return Status.ERROR

    if len(jsonData['data']['http']) == 0:
        return Status.EMPTY

    if 'response' not in data['data']['http']:
        return Status.NO_RESPONSE

    http_response = data['data']['http']['response']
    if 'body' in http_response:
        for str in parking_strings:
            if str in http_response['body']:
                return Status.PARKED_HTTP

    http_status_code = http_response['status_code']
    if 400 <= http_status_code < 500:
        return Status.RESPONSE_400

    if 500 <= http_status_code < 600:
        return Status.RESPONSE_500

    return Status.NOERROR


protocol_urls = {"http": set(), "https": set()}
protocol_domains = {"http": set(), "https": set()}

domain_histories = {}

parking_regex = re.compile('park|sell|sale|expier|expire', re.IGNORECASE)
sinkhole_regex = re.compile('sink', re.IGNORECASE)


def likely_parking(nameservers):
    for ns in nameservers:
        m = parking_regex.search(ns)
        if m:
            return True

    return False


def likely_sinkhole(nameservers):
    for ns in nameservers:
        m = sinkhole_regex.search(ns)
        if m:
            return True

    return False


def get_nameservers(data, domain):
    name = data['name']
    status = data['status']

    nameservers = set()

    if status == "NOERROR":
        for trace in data['trace']:
            if trace['name'] != name:
                continue
            for resp_type, rrs in trace['results'].items():
                if resp_type not in ['answers', 'additionals', 'authorities']:
                    continue

                for rr in rrs:
                    if 'name' not in rr:
                        continue

                    if rr['type'] == "NS" and rr['name'] == name and 'answer' in rr:
                        nameservers.add(rr['answer'])

    return nameservers


whitelist = set()
with open(whitelist_fpath) as f:
    reader = csv.DictReader(f)
    for row in reader:
        whitelist.add(row['FQDN'])
        whitelist.add(row['e2LD'])

# ns_count = 0
# parking_ns_count = 0
domains = set()
domains_with_ns = set()
domains_with_parking_ns = set()
http_noerror_domains = set()
https_noerror_domains = set()
longitudinal_status_counts = {}

for rr_fpath in sorted(glob.glob(os.path.join(blacklist_dir, "*/RR.json")))[0::7]:
    date = rr_fpath.split('/')[-2]
    d = datetime.strptime(date, '%Y-%m-%d')
    if d < datetime(2018, 11, 6) or d > datetime(2020, 3, 8):
        continue

    banner_fpath = rr_fpath.replace("RR.json", "banners.json")

    parking_ns_domains = set()
    logger.info(f"reading {rr_fpath}")
    with open(rr_fpath) as f:
        for line in f:
            if line == "null\n" or len(line) == 0:
                continue

            data = ujson.loads(line.rstrip())
            name = data['name']
            if name not in whitelist:
                continue

            domains.add(name)
            nameservers = get_nameservers(data, name)

            if len(nameservers) == 0:
                continue

            domains_with_ns.add(name)

            if likely_parking(nameservers):
                domains_with_parking_ns.add(name)
                parking_ns_domains.add(name)

    if not date in longitudinal_status_counts:
        longitudinal_status_counts[date] = {
            Status.ERROR: 0,
            Status.EMPTY: 0,
            Status.NO_RESPONSE: 0,
            Status.RESPONSE_400: 0,
            Status.RESPONSE_500: 0,
            Status.PARKED_HTTP: 0,
            Status.PARKED_DNS: 0,
            Status.NOERROR: 0,
        }

    logger.info(f"reading {banner_fpath}")
    with open(banner_fpath) as f:
        for line in f:
            if line == "null\n":
                continue

            data = ujson.loads(line.rstrip())
            domain = data['domain']
            if domain not in whitelist:
                continue

            url = data['url']
            protocol = url.split(":")[0]

            status = page_classification(data, domains_with_parking_ns)

            if status not in longitudinal_status_counts[date]:
                longitudinal_status_counts[date][status] = 0
            longitudinal_status_counts[date][status] += 1

            if status == status.NOERROR:
                if protocol == 'http':
                    http_noerror_domains.add(protocol)

                if protocol == 'https':
                    https_noerror_domains.add(protocol)

                print(line.strip())

    with open('blacklist-stats.txt', 'a') as f:
        statuses = longitudinal_status_counts[date]
        f.write(f"{date},{statuses[Status.ERROR]},{statuses[Status.EMPTY]},{statuses[Status.NO_RESPONSE]},{statuses[Status.RESPONSE_400]},{statuses[Status.RESPONSE_500]},{statuses[Status.PARKED_HTTP]},{statuses[Status.PARKED_DNS]}\n")
        # if not domain in domain_histories:
        #     domain_histories[domain] = DomainHistory(domain)
        #
        # domain_histories[domain].add_date(date, protocol)
        #
        # protocol_urls[protocol].add(":".join(url.split(":")[1:]))
        # protocol_domains[protocol].add(domain)

logger.info(f"domains: {len(domains)}")
logger.info(f"domains_with_ns: {len(domains_with_ns)}")
logger.info(f"domains_with_parking_ns: {len(domains_with_parking_ns)}")
logger.info(f"http_noerror_domains: {len(http_noerror_domains)}")
logger.info(f"https_noerror_domains: {len(https_noerror_domains)}")


# with open("/Users/zanema/src/malicious-certificates/data/parked-banners.no_errors.json") as f:
#     for line in f:
#         if line == "null\n":
#             continue
#
#         data = ujson.loads(line.rstrip())
#         domain = data['domain']
#
#         url = data['url']
#         protocol = url.split(":")[0]
#
#         status = page_classification(data, domains_with_parking_ns)
#
#         if status == status.NOERROR:
#             print(line.strip())


# print('-'*40 + "URLS" + '-'*40)
# print(f"HTTP: {len(protocol_urls['http'])}")
# print(f"HTTPS: {len(protocol_urls['https'])}")
# url_intersection = protocol_urls['http'].intersection(protocol_urls['https'])
# print(f"HTTPS and HTTP: {len(url_intersection)}")
#
# print('-'*40 + "Domains" + '-'*40)
# print(f"HTTP: {len(protocol_domains['http'])}")
# print(f"HTTPS: {len(protocol_domains['https'])}")
# domain_intersection = protocol_domains['http'].intersection(protocol_domains['https'])
# print(f"HTTPS and HTTP: {len(domain_intersection)}")
#
# print('-'*40 + "Domain histories" + '-'*40)
# transition_count = 0
# for domain, dh in domain_histories.items():
#     transition_date = dh.transitioned_to_http()
#     if transition_date != None:
#         transition_count += 1
#         print(f"{domain},{transition_date}")
#
# print(f"{transition_count} transitions from HTTPS to HTTP")
