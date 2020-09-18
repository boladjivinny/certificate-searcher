import csv
import tldextract

filename = "alexa-top-1k-20200526.csv"  

common_words = {'adobe', 
'academia',
'amazon',
'android',
'apple',
'archive',
'audible',
'battle',
'blackboard',
'blizzard',
'blogger',
'booking',
'cambridge',
'chase',
'chess',
'china',
'consultant',
'discord',
'discuss',
'entrepreneur',
'fandom',
'focus',
'force',
'genius',
'heavy',
'indeed',
'india',
'informer',
'intuit',
'medium',
'messenger',
'mobile',
'notion',
'office',
'oracle',
'orange',
'patch',
'rambler',
'realtor',
'remove',
'slack',
'storm',
'study',
'target',
'tinder',
'twitch',
'weather',
}

common_suffix = {'xvideos', 'nytimes', 'myway'}

with open(filename) as f: 
	reader = csv.reader(f)
	for row in reader: 
		rank = row[0]
		hostname = row[1]
		subdomain, e2LD, eTLD = tldextract.extract(hostname)

		if len(e2LD) < 5:
			continue
		
		if e2LD in common_words or e2LD in common_suffix:
			continue

		print(hostname)
