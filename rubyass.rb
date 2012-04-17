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
  cmd.gsub!(/\$port_open/, 	config[:open_ports][:tcp].first.to_s)
  cmd.gsub!(/\$repeat/, 	config[:repeat].to_s)
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


# test config
config[:open_ports][:tcp] << 80 

# init logger
logger = Logger.new(config[:target])

# display target
puts bold, "Target: #{config[:target]}", reset

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
  puts green, "  #{cmd}", reset

  logger.log("", false)
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

  # run checks on output
  if test[:checks]
    test[:checks].each do |check|
      # prepare output
      puts; puts
      print bold, check[:name], reset
      forward = 80 - check[:name].length
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
        print matches
        logger.result(matches);
      end 

    end
  end

  # seperator
  puts; hr;
end


logger.result("\nTests completed #{Time.now}")


# summary
puts
print green, "  #{count_checks_succ} passed / "
print yellow, " #{count_checks_fail} failed", reset
puts
hr
puts

exit 0
