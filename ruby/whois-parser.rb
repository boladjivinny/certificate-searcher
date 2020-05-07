#!/usr/bin/env ruby

require 'logger'
require 'optparse'
require 'whois-parser'
require 'yaml'

logger = Logger.new(STDOUT)

params = {}
OptionParser.new do |opts|
  opts.banner = "Usage whois.rb [options] "
  opts.on("-d", "--directory DIR", "DIR for storing whois records")
  puts opts if ARGV.length == 0
end.parse!(into: params)

Dir.entries(params[:directory]).select {|f| !File.directory? f}.each do |fname|
  fpath = File.join(params[:directory], fname)
  domain = fname
  serialized_obj = File.read(fpath)
  whois_record = YAML::load(serialized_obj)
  parser = whois_record.parser

  begin
    if parser.respond_to?('admin_contacts') && parser.admin_contacts.any?
      logger.info("#{domain}|#{parser.admin_contacts.map(&:email)}")
    end
  rescue Whois::AttributeNotSupported => e
    logger.warn(e)
  end
end