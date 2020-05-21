#/bin/bash

for f in $(rg -i "request limit exceeded"  -l); do rm $f; done
for f in $(rg -i "Query limit exceeded"  -l); do rm $f; done
for f in $(rg -i "Look up quota exceeded"  -l); do rm $f; done
for f in $(rg -i "exceeded the maximum allowable"  -l); do rm $f; done
for f in $(rg -i "exceeded the query limit for your"  -l); do rm $f; done
for f in $(rg -i "Your connection limit exceeded"  -l); do rm $f; done
for f in $(rg -i "Query rate exceeded, please try again later"  -l); do rm $f; done
for f in $(rg -i "WHOIS QUERY RATE LIMIT EXCEEDED"  -l); do rm $f; done
for f in $(rg -i "can temporarily not be"  -l); do rm $f; done
for f in $(rg -i "answered. Please try again"  -l); do rm $f; done