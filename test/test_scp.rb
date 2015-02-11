require 'minitest/autorun'

require 'sshfwd/server'
require 'sshfwd/scpinputoutputfilter'

require 'socket'
require 'pty'
require 'expect'
require 'fileutils'

class SshFwdBaseTest < MiniTest::Unit::TestCase
  def loglevel
    :warn
  end

  def debug(&block)
    case loglevel
    when :debug
      str = yield
      puts str
    end
  end

  def user
    'foo'
  end

  def pwd
    'foopwd'
  end

  def sshopts
    sshloglevel = { debug: 'DEBUG3', warn: 'INFO' }
    options = {
      LogLevel: sshloglevel[loglevel] || loglevel.to_s.upcase,
      UserKnownHostsFile:'/dev/null', 
      StrictHostKeyChecking:'no',
      ServerAliveInterval:1000}
    args = options.map { |k,v| "-o #{k.to_s}=#{v}" }
    args << '-vvvv' if loglevel == :debug
    args.join(' ')
  end

  def do_ssh(options={})
    host = options[:host]
    port = options[:port]
    command = options[:scp]
    user = options[:user] || user
    password = options[:password] || pwd
    params = options[:params]

    command = "scp #{sshopts} -P #{port} #{params}"
    debug { command }
    status = nil

    PTY.spawn(command) do |reader, writer, pid|
      begin
        reader.expect(/password:.*/) { |data| puts data }
        writer.puts(password)
        until reader.eof? do
          puts reader.readline
        end
      rescue Errno::EIO => e
      end
      pid, status = Process.wait2 pid
    end
    status.exitstatus
  end

  def start_server(options={},fwd_options={})
    @server = TCPServer.new 0
    @port,@host = @server.addr[1..2]
    @fwd_server = SSHFwd::Server.new(
      {server:@server,verbose: loglevel}.merge(options),
      {verbose: loglevel, ssh: {port: 22}, host: 'localhost'}.merge(fwd_options))
    @server_thread = Thread.new do
      @fwd_server.run
    end
  end

  def teardown
    @fwd_server.stop
    @server_thread.join
  end
end

class ScpForwardTest < SshFwdBaseTest
  def test_scp_works
    start_server

    src_file = '/tmp/foo.txt'
    dst_file = '/tmp/foo.txt.cp'
    content = "tmp#{Time.now.to_i}"
    File.open(src_file, File::CREAT|File::TRUNC|File::RDWR, 0664) {|f| f.write(content) }

    ec = do_ssh(host:@host,port:@port,command:'scp',params:"#{src_file} #{user}@#{@host}:#{dst_file}")

    assert_equal(0,ec)
    assert_equal(content,File.open(dst_file,'r').read())
  end


  class TestScpFilter < ScpInputOutputFilter
    attr_accessor :filenames

    def handle_c_directive(line)
      filenames << line.split(' ')[2] if filenames
      if File.basename(line.split(' ')[2]) == 'secret.txt'
        {action: :terminate, reply: "BAD"}
      else
        nil
      end
    end
  end

  def test_scp_captures_filename
    filenames = []
    start_server({},{
      create_filter: ->(request_type, options = {}) {
        case request_type
          when 'exec'
            command = options[:packet].read_string
            filter = TestScpFilter.new(command)
            filter.filenames = filenames
            {client:filter,server:filter}
        end
      }
    })

    FileUtils::mkdir_p "/tmp/src"
    src_file = "/tmp/src/foo#{Time.now.to_i}.txt"
    src_file2 = "/tmp/src/foo2_#{Time.now.to_i}.txt"
    dst_dir = "/tmp/"
    dst_file = File.join(dst_dir, File.basename(src_file))

    content = "content:tmp#{Time.now.to_i}"
    File.open(src_file, File::CREAT|File::TRUNC|File::RDWR, 0664) {|f| f.write(content) }
    File.open(src_file2, File::CREAT|File::TRUNC|File::RDWR, 0664) {|f| f.write(content) }

    ec = do_ssh(host:@host,port:@port,command:'scp',params:"#{src_file} #{src_file2} #{user}@#{@host}:/tmp/")

    assert_equal(0,ec)
    assert_equal(content,File.open(dst_file,'r').read())
    assert_equal(filenames,[File.basename(src_file),File.basename(src_file2)])
  end

  def test_scp_prevent_file_upload
    start_server({},{
      create_filter: ->(request_type, options = {}) {
        case request_type
          when 'exec'
            command = options[:packet].read_string
            filter = TestScpFilter.new(command)
            {client:filter,server:filter}
        end
      }
    })

    FileUtils::mkdir_p "/tmp/src", mode: 0770
    FileUtils::mkdir_p "/tmp/dst", mode: 0770
    src_file = "/tmp/src/secret.txt"
    dst_file = "/tmp/dst/secret.txt"
    FileUtils::rm_f dst_file

    File.open(src_file, File::CREAT|File::TRUNC|File::RDWR, 0664) {|f| f.write('secret') }
    ec = do_ssh(host:@host,port:@port,command:'scp',params:"#{src_file} #{user}@#{@host}:/tmp/dst/")

    assert_equal(1,ec)
    assert_equal(false,File.exists?(dst_file))
  end
end