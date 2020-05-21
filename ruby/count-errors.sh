#/bin/bash

rg -i "WHOIS LIMIT EXCEEDED" -c -N --no-filename | paste -s -d+ - | bc
rg -i "request limit exceeded" -c -N --no-filename | paste -s -d+ - | bc
rg -i "Query limit exceeded" -c -N --no-filename | paste -s -d+ - | bc
rg -i "Look up quota exceeded" -c -N --no-filename | paste -s -d+ - | bc
rg -i "exceeded the maximum allowable" -c -N --no-filename | paste -s -d+ - | bc
rg -i "exceeded the query limit for your" -c -N --no-filename | paste -s -d+ - | bc
rg -i "Your connection limit exceeded" -c -N --no-filename | paste -s -d+ - | bc
rg -i "Query rate exceeded, please try again later" -c -N --no-filename | paste -s -d+ - | bc
rg -i "WHOIS QUERY RATE LIMIT EXCEEDED" -c -N --no-filename | paste -s -d+ - | bc
rg -i "can temporarily not be" -c -N --no-filename | paste -s -d+ - | bc
rg -i "answered. Please try again" -c -N --no-filename | paste -s -d+ - | bc

