import csv
import glob
import os
import sys

blacklist_dir = sys.argv[1]
output_file = sys.argv[2]

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

for fpath in sorted(glob.glob(os.path.join(blacklist_dir, "*.csv"))):
    date = "-".join(fpath.split('/')[-1].split('-')[:2])

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
            eTLD_plus_one = row['ETLDPlus1']

            protocol_etldPlusOnes[date][protocol].add(eTLD_plus_one)
            protocol_domains[date][protocol].add(domain)

    with open(output_file, "a") as w:
        writer = csv.writer(w, quoting=csv.QUOTE_MINIMAL)
        http_etldPlusOnes = len(protocol_etldPlusOnes[date]["http"])
        https_etldPlusOnes = len(protocol_etldPlusOnes[date]["https"])
        percent_https_etldPlusOnes = https_etldPlusOnes / (https_etldPlusOnes + https_etldPlusOnes)

        http_domains = len(protocol_domains[date]["http"])
        https_domains = len(protocol_domains[date]["https"])
        percent_https_domains = https_domains / (https_domains + https_domains)

        writer.writerow(
            [date, http_domains, https_domains, percent_https_domains, http_etldPlusOnes, https_etldPlusOnes,
             percent_https_etldPlusOnes])

for date in sorted(protocol_etldPlusOnes):
    http_etldPlusOnes = len(protocol_etldPlusOnes[date]["http"])
    https_etldPlusOnes = len(protocol_etldPlusOnes[date]["https"])
    percent_https_etldPlusOnes = https_etldPlusOnes / (https_etldPlusOnes + https_etldPlusOnes)

    http_domains = len(protocol_domains[date]["http"])
    https_domains = len(protocol_domains[date]["https"])
    percent_https_domains = https_domains / (https_domains + https_domains)

    print(
        f"{date},{http_domains},{https_domains},{percent_https_domains},{http_etldPlusOnes},{https_etldPlusOnes},{percent_https_etldPlusOnes}")