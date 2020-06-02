import csv
import sys

from tldextract import tldextract
import ujson
from loguru import logger

url_domains_fpath = sys.argv[1]
banners_fpath = sys.argv[2]
output_certs_fpath = sys.argv[3]

# http redirect to https
# straight http
# https downgrade to http
# straight https

seen_certificates = set()
originally_http = set()
originally_https = set()
unlisted_protocol = set()
redirected_new_e2lds = set()
http_e2LDs = set()
https_e2LDs = set()

with open(url_domains_fpath) as f:
    reader = csv.DictReader(f)
    for row in reader:
        protocol = row['protocol']
        e2LD = row['e2LD']
        if protocol == "":
            unlisted_protocol.add(e2LD)
        elif protocol == 'http':
            originally_http.add(e2LD)
        elif protocol == 'https':
            originally_https.add(e2LD)

with open(banners_fpath) as f, open(output_certs_fpath, 'w') as w:
    cert_writer = csv.writer(w)
    stats_writer = csv.writer(sys.stdout)
    current_date = ""
    for line in f:
        if line == "null\n":
            continue

        data = ujson.loads(line.rstrip())
        date_str = data['timestamp'][:10]
        if current_date == "":
            current_date = date_str

        if date_str != current_date:
            logger.info(f"processing date {date_str}")
            stats_writer.writerow([
                current_date,
                len(http_e2LDs),
                len(https_e2LDs),
                len(redirected_new_e2lds),
            ])
            http_e2LDs = set()
            https_e2LDs = set()
            redirected_new_e2lds = set()
            current_date = date_str

        domain = data['domain']
        e2LD = ".".join(tldextract.extract(domain)[1:])
        url = data['url']
        protocol = url.split(":")[0]

        response = data['data']['http']['response']
        response_e2LD = ".".join(tldextract.extract(response['request']['url']['host'])[1:])
        response_protocol = response['request']['url']['scheme']

        if e2LD != response_e2LD:
            redirected_new_e2lds.add(e2LD)
            continue

        if response_protocol == 'http':
            http_e2LDs.add(e2LD)

        if response_protocol == 'https':
            https_e2LDs.add(e2LD)
            try:
                certificates = response['request']['tls_handshake']['server_certificates']
                leaf = certificates['certificate']
                sha256 = leaf['parsed']['fingerprint_sha256']

                if sha256 in seen_certificates:
                    continue
                seen_certificates.add(sha256)

                issuer_dn = leaf['parsed']['issuer_dn']
                if not 'chain' in certificates:
                    cert_writer.writerow([
                        sha256,
                        issuer_dn,
                        ''
                    ])
                else:
                    chain = certificates['chain']
                    parent_subject_spki = ''
                    if len(chain) > 0:
                        parent_subject_spki = chain[0]['parsed']['spki_subject_fingerprint']

                    cert_writer.writerow([
                        sha256,
                        issuer_dn,
                        parent_subject_spki
                    ])
            except Exception as e:
                logger.warning(e)
