import csv
import glob
import os
import sys

import tldextract
from loguru import logger

blacklist_dir = sys.argv[1]
safebrowsing_dir = sys.argv[2]
output_file = sys.argv[3]


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


protocol_etldPlusOnes = {}
protocol_domains = {}

previous_http_e2ld = set()
previous_https_e2ld = set()

for fpath in sorted(glob.glob(os.path.join(blacklist_dir, "*.csv")))[0::7]:
    logger.info(f"reading {fpath}")
    date = "-".join(fpath.split('/')[-1].split('-')[:3])

    new_https = set()
    still_https = set()
    http_to_https = set()
    new_http = set()
    still_http = set()
    https_to_http = set()

    gsb_paths = glob.glob(os.path.join(safebrowsing_dir, date + "/", f"{date}T00*-results.txt"))
    if len(gsb_paths) == 0:
        continue

    gsb_path = gsb_paths[0]

    protocol_etldPlusOnes[date] = {"http": set(), "https": set()}
    protocol_domains[date] = {"http": set(), "https": set()}

    with open(fpath) as f:
        csv_reader = csv.DictReader(f)
        skipped_header = False
        for row in csv_reader:
            url = row['URL']
            protocol = row['Scheme']
            if protocol == "":
                continue
            domain = row['Host']
            source = row['Source']
            eTLD_plus_one = row['ETLDPlus1']
            mal_category = row['Category']

            if mal_category != "Phishing":
                continue

            protocol_etldPlusOnes[date][protocol].add(eTLD_plus_one)
            protocol_domains[date][protocol].add(domain)

            if protocol == "https":
                if eTLD_plus_one in previous_https_e2ld:
                    still_https.add(eTLD_plus_one)
                elif eTLD_plus_one in previous_http_e2ld:
                    http_to_https.add(eTLD_plus_one)
                else:
                    new_https.add(eTLD_plus_one)

            if protocol == "http":
                if eTLD_plus_one in previous_http_e2ld:
                    still_http.add(eTLD_plus_one)
                elif eTLD_plus_one in previous_https_e2ld:
                    https_to_http.add(eTLD_plus_one)
                else:
                    new_http.add(eTLD_plus_one)

    logger.info(f"reading {gsb_path}")
    with open(gsb_path) as gsb:
        csv_reader = csv.reader(gsb)
        for row in csv_reader:
            entry = row[0]
            category = row[2]

            if category != 'SOCIAL_ENGINEERING':
                continue

            if not entry.startswith('http://') and not entry.startswith('https://'):
                continue

            ext = tldextract.extract(entry)
            domain = '.'.join(ext).strip('.')
            eTLD_plus_one = '.'.join(ext[1:]).strip('.')

            protocol = entry.split(':')[0]

            protocol_domains[date][protocol].add(domain)
            protocol_etldPlusOnes[date][protocol].add(eTLD_plus_one)

            if protocol == "https":
                if eTLD_plus_one in previous_https_e2ld:
                    still_https.add(eTLD_plus_one)
                elif eTLD_plus_one in previous_http_e2ld:
                    http_to_https.add(eTLD_plus_one)
                else:
                    new_https.add(eTLD_plus_one)

            if protocol == "http":
                if eTLD_plus_one in previous_http_e2ld:
                    still_http.add(eTLD_plus_one)
                elif eTLD_plus_one in previous_https_e2ld:
                    https_to_http.add(eTLD_plus_one)
                else:
                    new_http.add(eTLD_plus_one)

    previous_http_e2ld = still_http | https_to_http | new_http
    previous_https_e2ld = still_https | http_to_https | new_https

    with open(output_file, "a") as w:
        writer = csv.writer(w, quoting=csv.QUOTE_MINIMAL)
        http_etldPlusOnes = len(protocol_etldPlusOnes[date]["http"])
        https_etldPlusOnes = len(protocol_etldPlusOnes[date]["https"])
        percent_https_etldPlusOnes = https_etldPlusOnes / (https_etldPlusOnes + http_etldPlusOnes)

        http_domains = len(protocol_domains[date]["http"])
        https_domains = len(protocol_domains[date]["https"])
        percent_https_domains = https_domains / (https_domains + http_domains)
        writer.writerow([
            date,
            http_domains,
            https_domains,
            percent_https_domains,
            http_etldPlusOnes,
            https_etldPlusOnes,
            percent_https_etldPlusOnes,
            len(new_http),
            len(https_to_http),
            len(still_http),
            len(new_https),
            len(http_to_https),
            len(still_https),
        ])

        w.flush()
