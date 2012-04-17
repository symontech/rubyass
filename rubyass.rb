#!/usr/bin/env ruby
require 'optparse'
require 'yaml'
require 'term/ansicolor'
include Term::ANSIColor

class Logger
  def initialize(target)
    @file_prefix = "logs/#{target}"
  end

  def log(message, date=true)
    File.open("#{@file_prefix}.log", 'a') do |f|
      if date
        f.puts("#{Time.now}\t#{message}")
      else
        f.puts(message)
      end
    end
  end

  def result(message, newline=true)
    File.open("#{@file_prefix}.result", 'a') do |f|
      f.print(message)
      f.print("\n") if newline
    end
  end
  
end


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
  cmd.gsub!(/\$target/, 	config[:target])
  if config[:open_ports][:tcp].first
    cmd.gsub!(/\$port_open/, 	config[:open_ports][:tcp].first[:port].to_s)
  end
  cmd.gsub!(/\$repeat/, 	config[:repeat].to_s)
  return cmd
end

# create ports hash using nmap output
def get_ports_from_output(output)
  ports = {:tcp => [], :udp => []}
  output.scan(/[\d]+\/tcp\W+open.*/).each do |line|
    elements = line.split
    set = {:port => elements[0].to_i, :service => "", :banner => "" }
    set[:service] = elements[2] if elements[2]
    set[:banner]  = elements[3..-1].join(" ") if elements[3]
    ports[:tcp] << set
  end
  output.scan(/[\d]+\/udp\W+open.*/).each do |line|
    elements = line.split
    set = {:port => elements[0].to_i, :service => "", :banner => "" }
    set[:service] = elements[2] if elements[2]
    set[:banner]  = elements[3..-1].join(" ") if elements[3]
    ports[:udp] << set
  end
  #puts ports.to_yaml
  return ports
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
  error "please specify a target"
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
	:repeat => 3,
	:open_ports => {:tcp => [], :udp => [] },
}


# init logger
logger = Logger.new(config[:target])

# display target
#puts bold, "Target: #{config[:target]}", reset

logger.log("Target: #{config[:target]}")
logger.result("Tests on #{config[:target]} started #{Time.now}\n")


# stats
count_checks_succ = 0
count_checks_fail = 0


# start the tests
tests.each do |test|
  # replace vars and show command
  print yellow, "#{test[:name]}"
  cmd = replace_vars(test[:command], config)
  puts green, "# #{cmd}", reset

  logger.log("\n\n\n", false)
  logger.log(cmd)

  # run command and capture output
  output = "" 
  IO.popen (cmd) do |f|
    while(s = f.gets)
      output += s
    end
  end


  #puts output
  logger.log(output, false)

  if(test[:port_source])
    ports = get_ports_from_output(output)
    if ports[:tcp]
      ports[:tcp].each { |port| config[:open_ports][:tcp] << port unless config[:open_ports][:tcp].include?(port) }
    end
    if ports[:udp]
      ports[:udp].each { |port| config[:open_ports][:udp] << port unless config[:open_ports][:udp].include?(port) }
    end
  end

  # run checks on output
  if test[:checks]
    test[:checks].each do |check|
      # prepare output
      puts; puts
      print bold, check[:name], reset
      forward = 70 - check[:name].length
      forward = 1 if forward < 1
      spaces = ""
      forward.times { spaces += " " }
      print spaces
      print "["

      logger.result(check[:name], false)
      logger.result(spaces, false)
      logger.result("[", false)



      # eval
      matches = output.match(Regexp.new(check[:test]))
      passed = true if matches
      passed = !passed unless check[:match_passes]
      if passed
        print green, "OK"
        logger.result("OK", false)
	count_checks_succ += 1
      else
        print yellow, "FAILED"
        logger.result("FAILED", false)
        count_checks_fail += 1
      end
      print reset, "]\n"
      logger.result("]")
      
      if matches
        print "  #{matches}"
        logger.result("  #{matches}");
      end 

    end
  end

  # seperator
  puts; hr;
end


logger.result("\nTests completed #{Time.now}")

# show ports and services in result file
ports_count = config[:open_ports][:tcp].count + config[:open_ports][:udp].count
port_status = "\n#{ports_count} ports and services detected:"

port_list = []
config[:open_ports][:tcp].each { |port| port_list << port[:port] unless port_list.include?(port[:port]) }
config[:open_ports][:udp].each { |port| port_list << port[:port] unless port_list.include?(port[:port]) }
puts "port list for vulnerabilty scanner: #{port_list.join(',')}"


logger.result(port_status)
logger.result(config[:open_ports].to_yaml)


# summary
puts
print green, "  #{count_checks_succ} passed /"
print yellow, " #{count_checks_fail} failed", reset
puts
puts port_status
hr
puts

exit 0
