import csv
import sys
import tldextract

filename = sys.argv[1]

alexa_top_1k = set()
with open("alexa-top-100k-20200526.csv") as f:
	reader = csv.reader(f)
	for row in reader:
		hostname = row[1]
		alexa_top_1k.add(hostname)


with open(filename) as f:
	for line in f:
		hostname = line.strip()
		subdomain, e2ld, etld = tldextract.extract(hostname)

		if hostname in alexa_top_1k:
			continue

		print(hostname)