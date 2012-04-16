require 'yaml'
require 'term/ansicolor'
include Term::ANSIColor

def hr
	print blue
  80.times { print '-' }
	puts reset
end

hr

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

# load the tests from yaml
tests = YAML::load_file('tests.yml') rescue nil
if tests
  success "#{tests.length} tests loaded"
else
  error "no tests could be loaded"
	exit 1
end

config = {
	:target => '',
	:open_ports => {:tcp => [], :udp => [] },
}

# test config
config[:target] = "127.0.0.1"
config[:open_ports][:tcp] << 22 

puts bold, "target ip: #{config[:target]}", reset

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
