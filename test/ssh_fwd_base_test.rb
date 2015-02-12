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

  def sshopts(extra_opts)
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

    sshopts_str = sshopts(options[:sshopts]||{})
    command = "scp #{sshopts_str} -P #{port} #{params}"
    debug { command }
    puts "Comman:#{command}"
    status = nil

    outs = ''
    PTY.spawn(command) do |reader, writer, pid|
      begin
        reader.expect(/password:.*/) do |data|
          puts data
          outs << data.join('')
        end
        writer.puts(password)
        until reader.eof? do
          line = reader.readline
          puts line
          outs << line
        end
      rescue Errno::EIO => e
      end
      pid, status = Process.wait2 pid
    end
    [status.exitstatus, outs]
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
    puts "Server thread joined"
  end
end