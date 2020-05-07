#!/usr/bin/env ruby

require 'logger'
require 'optparse'
require 'parallel'
require 'set'
require 'whois-parser'
require 'yaml'

logger = Logger.new(STDOUT)

params = {}
OptionParser.new do |opts|
	opts.banner = "Usage whois.rb [options] "
	opts.on("-i", "--input INPUTFILE", "INPUTFILE with domains to look up")
  opts.on("-o", "--output OUTPUT_DIR", "OUTPUT_DIR for storing whois records")
	puts opts if ARGV.length == 0 
end.parse!(into: params)

whois_hosts_domains = {}
unknown_whois_host_domains = Set.new

File.readlines(params[:input]).each do |line|
	domain = line.rstrip.split(",")[0]
  host = Whois::Server.find_for_domain(domain)&.host

  if host.nil?
    unknown_whois_host_domains.add(domain)
  else
    whois_hosts_domains[host] = [] unless whois_hosts_domains.key?(host)
    whois_hosts_domains[host] << domain
  end
end

# sort whois_hosts to prioritize shorter domains (less likely to be a long chained dumb domain)
whois_hosts_domains.each do |whois_host, domains|
  whois_hosts_domains[whois_host] = domains.sort_by(&:length)
end

whois_hosts = whois_hosts_domains.keys
Parallel.map(whois_hosts, in_threads: whois_hosts.length) do |whois_host|
  whois_hosts_domains[whois_host].each do |domain|
    output_filename = File.join(params[:output], domain)
    next if File.exists?(output_filename)

    logger.info("Looking up WHOIS for #{domain} from #{whois_host}")
    record = Whois.whois(domain)
    serialized = YAML::dump(record)
    File.write(output_filename, serialized)
    sleep(10)
  end
end
