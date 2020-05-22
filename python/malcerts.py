import sys

import ujson

malcert_file = sys.argv[1]

#unique by tbs_noct_fingerprint
certs = set()
count = 0
with open(malcert_file) as f:
    for line in f:
        count += 1
        data = ujson.loads(line.rstrip())
        if not 'leaf_parent' in data:
            continue

        cert_fp = data['leaf']['tbs_noct_fingerprint']
        if cert_fp in certs:
            continue

        certs.add(cert_fp)

        abuse_domains = data['abuse_domains']
        abuse_types = set()
        for x, d in abuse_domains.items():
            abuse_types.update(d.keys())

        for abuse_type in abuse_types:
            print(f"{abuse_type},{data['leaf_parent']['spki_subject_fingerprint']},{data['leaf']['issuer_dn']},{data['leaf']['validity']['start']}")

