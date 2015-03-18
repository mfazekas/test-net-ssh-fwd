PORT = ENV['PORT']
PASSWORD = ENV['PASSWORD']
require 'benchmark'
require 'pty'
require 'expect'

def ssh_with_password(command,passwords)
  outs = []
  pid, status = [nil, nil]
  PTY.spawn(command) do |reader, writer, pid|
    begin
      while passwords.size > 0
        reader.expect(/password:.*/) do |data|
          if data
            puts data
            outs << data.join('')
          end
        end
        password = passwords.shift
        writer.puts(password)
      end
      until reader.eof? do
        line = reader.readline
        puts line
        outs << line
      end
    rescue Errno::EIO => e
    end
    pid, status = Process.wait2 pid
  end
  [pid,status]
end


size = 4*8*1024*1024 # 32*8MB
count = 1
total_size = count*size
total_size_mb = total_size / (1024*1024)
command = "dd if=/dev/random of=/tmp/bigfile bs=#{size} count=#{count}"
puts "command:#{command}"
system(command)

options = "-o Ciphers=aes128-cbc -vvvv"

options = ""
options = " -vvvv"
command = "scp -q -P #{PORT} #{options} /tmp/bigfile boga@localhost:/dev/null" #/tmp/bigfile.2
puts "command:#{command}"
status = nil
ret = Benchmark.measure { pid,status = ssh_with_password(command,[PASSWORD]) }
puts "Scp result:#{status.inspect} exitstatus:#{status.exitstatus}"
puts "Time:#{ret.real} s"
puts "Throughput:#{total_size_mb / ret.real} MB/s"
raise "Failed #{status.exitstatus}" unless status.exitstatus == 0