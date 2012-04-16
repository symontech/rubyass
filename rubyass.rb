#!/usr/bin/env ruby
require 'optparse'
require 'yaml'
require 'term/ansicolor'
include Term::ANSIColor

def hr
	print blue
  80.times { print '-' }
	puts reset
end

def error(message)
  puts red, bold, "ERROR: #{message}", reset
end

def success(message)
  puts green, message, reset
end

def replace_vars(cmd, config)
  cmd.gsub!(/\$target/, config[:target])
  cmd.gsub!(/\$port_open/, config[:open_ports][:tcp].first.to_s)
	return cmd
end

options = {
  :first       => "default value",
  :another     => 23,
  :bool        => false,
  :list        => ["x", "y", "z"],
  :dest        => File.expand_path(File.dirname($0))
}

ARGV.options do |o|
  script_name = File.basename($0)
  
  o.set_summary_indent('  ')
  o.banner =    "Usage: #{script_name} [OPTIONS] target"
  o.define_head "ruby basic security assessment"
  o.separator   ""
  #o.separator   "Mandatory arguments to long options are mandatory for " +
  #              "short options too."  
#  o.on("-f", "--first=[val]", String,
#       "A long and short (optional) string argument",
#       "Default: #{options[:first]}")   { |options[:first]| }
#  o.on("-a", "--another=val", Integer,
#       "Requires an int argument")      { |options[:another]| }
#  o.on("-b", "--boolean",
#       "A boolean argument")            { |options[:bool]| }
#  o.on("--list=[x,y,z]", Array, 
#       "Example 'list' of arguments")   { |options[:list]| }
  
  #o.separator ""

  o.on_tail("-h", "--help", "Show this help message.") { puts o; puts; exit }
  o.parse!
end

# target is required
unless ARGV.last
  error "no target"
  exit 1 
end

# load the tests from yaml
tests = YAML::load_file('tests.yml') rescue nil
if tests
  success "#{tests.length} tests loaded"
else
  error "no tests could be loaded" and exit 1
end

config = {
	:target => ARGV.last,
	:open_ports => {:tcp => [], :udp => [] },
}

# test config
#config[:target] = "127.0.0.1"
config[:open_ports][:tcp] << 22 

puts bold, "Target: #{config[:target]}", reset

# start the tests
tests.each do |test|

	# replace vars and show command
  puts yellow, "#{test[:name]}", reset
	cmd = replace_vars(test[:command], config)
	puts green, cmd, reset

	# run command and capture output
  output = "" 
	IO.popen (cmd) do |f| 
		while(s = f.gets)
	    puts s 
			output += s
		end
	end


	puts; hr;
end

exit 0
