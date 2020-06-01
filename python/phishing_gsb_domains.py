import csv
import glob
import os
import sys
from datetime import datetime

import tldextract
from loguru import logger

blacklist_dir = sys.argv[1]
safebrowsing_dir = sys.argv[2]
output_file = sys.argv[3]

fieldnames = ['URL', 'protocol', 'FQDN', 'e2LD', 'source']
with open(output_file, "w") as w:
    writer = csv.DictWriter(w, quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)
    writer.writeheader()

for fpath in sorted(glob.glob(os.path.join(blacklist_dir, "*.csv"))):
    date = "-".join(fpath.split('/')[-1].split('-')[:3])
    d = datetime.datetime.strptime(date, '%Y-%m-%d')
    if d > datetime(2020, 4, 1):
        continue

    logger.info(f"reading {fpath}")

    gsb_paths = glob.glob(os.path.join(safebrowsing_dir, date + "/", f"{date}T00*-results.txt"))
    if len(gsb_paths) == 0:
        continue

    gsb_path = gsb_paths[0]

    with open(output_file, "a") as w:
        writer = csv.DictWriter(w, quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)

        with open(fpath) as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                url = row['URL']
                protocol = row['Scheme']
                domain = row['Host']
                source = row['Source']
                eTLD_plus_one = row['ETLDPlus1']

                if source not in ['phishtank.com', 'openphish.com']:
                    continue

                writer.writerow({
                    'URL': url,
                    'protocol': protocol,
                    'FQDN': domain,
                    'e2LD': eTLD_plus_one,
                    'source': source,
                })

        logger.info(f"reading {gsb_path}")
        with open(gsb_path) as gsb:
            csv_reader = csv.reader(gsb)
            for row in csv_reader:
                entry = row[0]
                category = row[2]

                if category != 'SOCIAL_ENGINEERING':
                    continue

                ext = tldextract.extract(entry)
                domain = '.'.join(ext).strip('.')
                eTLD_plus_one = '.'.join(ext[1:]).strip('.')

                protocol = ''
                if entry.startswith('http://') or entry.startswith('https://'):
                    protocol = entry.split(':')[0]

                writer.writerow({
                    'URL': entry,
                    'protocol': protocol,
                    'FQDN': domain,
                    'e2LD': eTLD_plus_one,
                    'source': 'GSB',
                })
