#!/usr/bin/env ruby

require 'logger'
require 'oj'
require 'optparse'
require 'parallel'
require 'set'
require 'whois-parser'
require 'yaml'

logger = Logger.new(STDOUT)

params = {}
OptionParser.new do |opts|
	opts.banner = "Usage whois.rb [options] "
	opts.on("-i", "--input INPUTFILE", "INPUTFILE with domains to look up (can be malcerts json or domain txt)")
  opts.on("-o", "--output OUTPUT_DIR", "OUTPUT_DIR for storing whois records")
	puts opts if ARGV.length == 0 
end.parse!(into: params)

whois_hosts_domains = {}
unknown_whois_host_domains = Set.new

case File.extname(params[:input])
when ".txt"
  File.readlines(params[:input]).each do |line|
    domain = line.rstrip.split(",")[0]
    domain = domain[2..-1] if domain.start_with?("*.")
    host = Whois::Server.find_for_domain(domain)&.host

    if host.nil?
      unknown_whois_host_domains.add(domain)
    else
      whois_hosts_domains[host] = [] unless whois_hosts_domains.key?(host)
      whois_hosts_domains[host] << domain
    end
  end
when ".json"
  File.readlines(params[:input]).each do |line|
    obj = Oj.load(line.rstrip)
    obj['abuse_domains'].each do |maldomain, maltypes|
      # skip over google safe browsing / phishtank
      next unless (maltypes.keys & ["GOOGLE_SAFEBROWSING", "PHISHTANK"]).empty?

      maldomain = maldomain[2..-1] if maldomain.start_with?("*.")
      host = Whois::Server.find_for_domain(maldomain)&.host

      if host.nil?
        unknown_whois_host_domains.add(maldomain)
      else
        whois_hosts_domains[host] = [] unless whois_hosts_domains.key?(host)
        whois_hosts_domains[host] << maldomain
      end
    end
  end
else
  puts "Unsupported filetype: #{params[:input]}. Only json/txt are supported."
  exit(1)
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
    sleep(30)
  end
end
