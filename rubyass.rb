#!/usr/bin/env ruby
require 'optparse'
require 'yaml'
require 'term/ansicolor'
include Term::ANSIColor

def tested(what, success)
  print bold, what, reset
  forward = 70 - what.length
  forward = 1 if forward < 1
  spaces = ''
  forward.times { spaces += ' ' }
  print spaces
  print '['

  clean = "#{what}#{spaces}["

  if success
    print green, 'OK'
    clean += 'OK'
  else
    print yellow, 'FAILED'
    clean += 'FAILED'
  end
  print reset, "]\n"
  clean + ']'
end

def hr
  print blue
  80.times { print '-' }
  puts reset
end

# header
hr
puts blue, '  ruby basic network assessment tool', reset
hr

# check for installed tools
missing_any_tools = false

['sudo -V', 'nmap -version', 'hping3 -v'].each do |tool|
  success = system("#{tool} > /dev/null 2>&1")
  tested("checking for #{tool.split.first}", success)
  missing_any_tools = true unless success
end

if missing_any_tools
  puts yellow, bold, 'Please install missing tools and make sure the binaries are in the path.', reset
  Kernel.exit(1)
end

class Logger
  def initialize(target)
    @file_prefix = "logs/#{target}"
  end

  def log(message, date = true)
    File.open("#{@file_prefix}.log", 'a') do |f|
      if date
        f.puts("#{Time.now}\t#{message}")
      else
        f.puts(message)
      end
    end
  end

  def result(message, newline = true)
    File.open("#{@file_prefix}.result", 'a') do |f|
      f.print(message)
      f.print("\n") if newline
    end
  end
end

def error(message)
  puts red, bold, "ERROR: #{message}", reset
  Kernel.exit(1)
end

def success(message)
  puts green, message, reset
end

def replace_vars(cmd, config)
  cmd.gsub!(/\$target/, config[:target])
  if config[:open_ports][:tcp].first
    cmd.gsub!(/\$port_open/, config[:open_ports][:tcp].first[:port].to_s)
  end
  cmd.gsub(/\$repeat/, config[:repeat].to_s)
end

# create ports hash using nmap output
def get_ports_from_output(output)
  ports = { tcp: [], udp: [] }
  output.scan(%r{[\d]+\/tcp\W+open.*}).each do |line|
    elements = line.split
    set = { port: elements[0].to_i, service: '', banner: '' }
    set[:service] = elements[2] if elements[2]
    set[:banner]  = elements[3..-1].join(' ') if elements[3]
    ports[:tcp] << set
  end
  output.scan(%r{[\d]+\/udp\W+open.*}).each do |line|
    elements = line.split
    set = { port: elements[0].to_i, service: '', banner: '' }
    set[:service] = elements[2] if elements[2]
    set[:banner]  = elements[3..-1].join(' ') if elements[3]
    ports[:udp] << set
  end
  ports
end

def usage(script_name)
  "Usage: ./#{script_name} [OPTIONS] target"
end

options = {
  first:   'default value',
  another: 23,
  bool:    false,
  list:    %w[x y z],
  dest:    File.expand_path(File.dirname($PROGRAM_NAME))
}

script_name = File.basename($PROGRAM_NAME)
ARGV.options do |o|
  o.set_summary_indent('  ')
  o.banner =    usage(script_name)
  o.define_head 'ruby basic security assessment'
  o.separator   ''
  o.on_tail('-h', '--help', 'Show this help message.') do
    puts o
    puts
    exit
  end
  o.parse!
end

# target is required
error "please specify a target. \n#{usage(script_name)}" unless ARGV.last

# load the tests from yaml
hr
if (tests = YAML.load_file('tests.yml'))
  tested("loaded #{tests.length} tests", true)
else
  tested('load tests', false)
  error 'no tests could be loaded'
end

config = {
  target: ARGV.last,
  repeat: 3,
  open_ports: { tcp: [], udp: [] }
}

# init logger
logger = Logger.new(config[:target])
logger.log("Target: #{config[:target]}")
logger.result("Tests on #{config[:target]} started #{Time.now}\n")

# stats
count_checks_succ = 0
count_checks_fail = 0

# start the tests
tests.each do |test|
  # replace vars and show command
  print yellow, test[:name].to_s
  cmd = replace_vars(test[:command], config)
  puts green, "# #{cmd}", reset

  logger.log("\n\n\n", false)
  logger.log(cmd)

  # run command and capture output
  output = ''
  IO.popen(cmd) do |f|
    while (s = f.gets)
      output += s
    end
  end

  logger.log(output, false)

  if test[:port_source]
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
      puts
      puts

      # eval
      matches = output.match(Regexp.new(check[:test]))
      passed = true if matches
      passed = !passed unless check[:match_passes]

      clean = tested(check[:name], passed)
      logger.result(clean)

      if passed then count_checks_succ += 1
      else count_checks_fail += 1
      end

      if matches
        print "  #{matches}"
        logger.result("  #{matches}")
      end
    end
  end

  # seperator
  puts
  hr
end

# finalize
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

# print summary
puts
print green, "  #{count_checks_succ} passed /"
print yellow, " #{count_checks_fail} failed", reset
puts
puts port_status
hr
puts
