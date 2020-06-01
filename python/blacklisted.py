import csv
import glob
import os
import re
import sys
from datetime import datetime
from loguru import logger

import ujson

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

    # http_status_code = http_response['status_code']
    # if 400 <= http_status_code and http_status_code < 500:
    #     return Status.RESPONSE_400
    #
    # if 500 <= http_status_code and http_status_code < 600:
    #     return Status.RESPONSE_500

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
        longitudinal_status_counts[date] = {}

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

            if status == status.PARKED_DNS:
                print(line.strip())

            # if not domain in domain_histories:
            #     domain_histories[domain] = DomainHistory(domain)
            #
            # domain_histories[domain].add_date(date, protocol)
            #
            # protocol_urls[protocol].add(":".join(url.split(":")[1:]))
            # protocol_domains[protocol].add(domain)

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
