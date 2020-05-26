#!/usr/bin/env ruby

require 'logger'
require 'oj'
require 'optparse'
require 'whois-parser'
require 'yaml'

logger = Logger.new(STDOUT)

params = {}
OptionParser.new do |opts|
  opts.banner = "Usage whois.rb [options] "
  opts.on("-d", "--directory DIR", "DIR for storing whois records")
  opts.on("-b", "--base_directory BDIR", "BDIR for storing base whois records")
  opts.on("-i", "--input INPUT", "INPUT malcert json file")
  puts opts if ARGV.length == 0
end.parse!(into: params)

base_admin_emails = {}
email_regex = Regexp.new('[a-zA-Z0-9\.\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+')
privacy_emails = %w[proxy-privacy.com domainsbyproxy.com whoisprivacy.com domains-anonymizer.com whoisguard.com safenames.net networksolutionsprivateregistration.com abuse@web.com contactprivacy.com contact.gandi dnstinations.com contactprivacy.email dataprivacyprotected@1und1.de privacyprotect.org expiredsupport@namecheap.com whoisprotection.domains domain-contact.org dditservices.com whoisprivacyprotect.com domains@instructure.com myprivacy.net]
Dir.entries(params[:base_directory]).select { |f| !File.directory? f }.each do |fname|
  fpath = File.join(params[:base_directory], fname)
  domain = fname
  serialized_obj = File.read(fpath)
  whois_record = YAML::load(serialized_obj)

  base_admin_emails[domain] = whois_record.parts.map do |part|
    admin_emails = part.body.split("\n").map do |line|
      line = line.downcase
      if line.include? 'admin' and email_regex.match?(line)
        email_regex.match(line)[0]
      else
        nil
      end
    end.select(&:present?)

    admin_emails = admin_emails.uniq
    if admin_emails.length == 0
      nil
    elsif admin_emails.length == 1
      if domain == "livedoor.jp"
        "dl_livedoor_support@linecorp.com" #TODO: keep an eye on this
      elsif privacy_emails.select { |e| admin_emails[0].include? e }.any?
        nil
      else
        admin_emails[0]
      end
    elsif domain == "google.fr"
      "dns-admin@google.com"
    elsif domain == "speedtest.net"
      "hostmaster@ziffdavis.com"
    else
      emails = admin_emails.join(",")
      "MULTIPLE ADMIN EMAILS FOR #{domain}: #{emails}"
    end
  end.select(&:present?)
end

File.readlines(params[:input]).each do |line|
  line = line.strip
  next if line.length == 0
  obj = Oj.load(line.rstrip)
  obj['abuse_domains'].each do |maldomain, maltypes|
    # skip over google safe browsing / phishtank
    next unless (maltypes.keys & ["GOOGLE_SAFEBROWSING", "PHISHTANK"]).empty?

    maldomain = maldomain[2..-1] if maldomain.start_with?("*.")
    base_domains = []
    maltypes.each do |k, v|
      base_domains += v
    end
    base_domains = base_domains.flatten.uniq
    admin_emails = base_domains.map do |domain|
      base_admin_emails[domain]
    end.flatten.uniq.select(&:present?)

    next unless admin_emails.length > 0

    fpath = File.join(params[:directory], maldomain)
    next unless File.file?(fpath)
    whois_record = YAML::load(File.read(fpath))
    shared_ownership = whois_record.parts.select do |part|
      admin_emails.select { |a| part.body.include? a }.any?
    end.any?

    unless shared_ownership
      puts line
    end
  end
end

