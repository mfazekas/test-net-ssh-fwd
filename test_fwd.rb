ENABLE_KERBEROS = ENV['NO_KRB'] ? false : true
ENABLE_FORWARD = true
puts "kerberos:#{ENABLE_KERBEROS}"
$:.push(ENV['NET_SSH_DIR'] || './net-ssh/lib')
$:.push(ENV['GSSAPI_DIR'] || './gssapi/lib/') if ENABLE_KERBEROS
$:.push(ENV['NET_SSH_KERBEROS_DIR'] || './net-ssh-kerberos/lib/') if ENABLE_KERBEROS
require 'net/ssh'
require 'net/ssh/server'
require 'net/ssh/server/keys'
require 'net/ssh/transport/server_session'
require 'net/ssh/server/channel_extensions'
require 'socket'
require 'ostruct'
require 'byebug'

if ENABLE_KERBEROS
  require 'net/ssh/kerberos'
end


PORT = 2000
Thread.abort_on_exception=true

logger = Logger.new(STDERR)
logger.level = Logger::DEBUG
logger.level = Logger::WARN unless (ENV['DEBUG'] && ENV['DEBUG'].include?('S'))

puts "Setting up server keys..."
server_keys = Net::SSH::Server::Keys.new(logger: logger, server_keys_directory: '.')
server_keys.load_or_generate

puts "Listening on port #{PORT}..."

class AuthLogic
  def allow_password?(username,password,options)
    password == username+'pwd'
  end

  def allow_none?(username,options)
    username == 'foo'
  end
end

class DummyFwdConnection
  include Net::SSH::Loggable

  def initialize(host,options)
    @options = options
  end

  def process
  end

  def connect
  end

  def handle(connection)
  end
end

class FwdConnection
  include Net::SSH::Loggable

  module FwdChannelExtensions
    def fwd_channel
      @fwd_channel
    end
    def fwd_channel=(value)
      @fwd_channel=value
    end
  end

  def initialize(host,options)
    @host = host
    @options = options
    alogger = Logger.new(STDERR)
    alogger.level = Logger::DEBUG
    alogger.level = Logger::WARN unless (ENV['DEBUG'] && ENV['DEBUG'].include?('F'))
    alogger.formatter = proc { |severity, datetime, progname, msg| "[FWD] #{datetime}: #{msg}\n" }
    options[:logger] = alogger
    self.logger = alogger
  end

  def connect
    @transport = Net::SSH::Transport::Session.new(@host, @options)
    @transport.socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
  end

  def _init_connection
    @fwd_conn = Net::SSH::Connection::Session.new(@transport, @options)
  end

  def allow_password?(username,password,options)
    @auth = Net::SSH::Authentication::Session.new(@transport, @options)
    if @auth.authenticate(options[:next_service], username, password) 
      _init_connection
    end
  end

  def allow_kerberos?(username,srv,options)
    if delegated_credentials = srv.delegated_credentials
      @auth = Net::SSH::Authentication::Session.new(@transport, @options.merge(auth_methods: ["gssapi-with-mic"],
        gss_delegated_credentials: delegated_credentials))
      debug { "_auth started to upstream "}
      if @auth.authenticate(options[:next_service], username)
        debug { "_auth finished to upstream "}
        debug { "_init_connection before" }
        _init_connection
        debug { "_init_connection after" }
        true
      else
        false
      end
    else
      error { "Could not delegate credentials" }
      false
    end
  end

  def allow_none?(username,options)
    false
  end

  def _supported_requests
    ['shell','exec','pty-req','env']
  end

  def _fwd_channel(channel)
    result = channel.fwd_channel
    while result.nil? do
      timeout = 0.001
      debug { "waiting for fwd hannel "}
      @fwd_conn.process(timeout)
      result = channel.fwd_channel
    end
    return result
  end

  def _handle_channel(channel)
    _supported_requests.each do |request_type|
      channel.on_request request_type do |channel,data,options|
        _fwd_channel(channel).on_data do |fwd_channel,data|
          #puts "#{request_type}: data from server => client"
          debug { "data from fwd   -> : #{data}"}
          channel.send_data(data)
          channel._flush
        end
        channel.on_data do |channel,data|
          debug { "data from client -> : #{data}"}
          #puts "#{request_type}: data from client => server"
          fwd_channel = _fwd_channel(channel)
          fwd_channel.send_data(data)
          fwd_channel._flush
        end
        if options[:want_reply]
          _fwd_channel(channel).send_channel_request(request_type,:raw,data.read) do |fwd_ch, success|
            channel.send_reply(success)
            options[:want_reply] = false
          end
        else
          _fwd_channel(channel).send_channel_request(request_type,:raw,data.read)
        end
      end
    end
  end

  def process
    @fwd_conn.process(nil) if @fwd_conn
  end

  def handle(connection)
    connection.on_open_channel('session') do |session, channel, packet|
      channel.extend(Net::SSH::Server::ChannelExtensions)
      channel.extend(FwdChannelExtensions)
      _handle_channel(channel)
      debug { "received open_channel from client" }
      @fwd_conn.open_channel('session') do |fwd_channel|
        debug { "opened channel on fwd! setting:#{fwd_channel}" }
        channel.fwd_channel=fwd_channel
      end
      debug { "reply open_channel to client" }
    end
  end
end

Thread.start do
  server = TCPServer.new PORT
  header = []
  auth_logic = AuthLogic.new
  loop do
    Thread.start(server.accept) do |client|
      client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      options = {}
      options[:logger] = logger
      options[:server_side] = true
      options[:server_keys] = server_keys.keys
      options[:host_key] = server_keys.types
      options[:kex] = ['diffie-hellman-group-exchange-sha256']
      options[:hmac] = ['hmac-md5']
      options[:auth_logic] = auth_logic
      options[:listeners] = {}
      if ENABLE_KERBEROS
        options[:allowed_auth_methods] = ['gssapi-with-mic']
        options[:gss_server_host] = 'precise32.fazmic.com'
        options[:gss_server_service] = 'host'
        options[:gss_server_servicekeytab] = '/etc/krb5.keytab'
      end

      fwd_options = {}
      fwd_options[:listeners] = options[:listeners]
      fwd_host = 'localhost'

      if ENABLE_FORWARD
        fwd_connection = FwdConnection.new(fwd_host,fwd_options)
      else
        fwd_connection = DummyFwdConnection.new(fwd_host,fwd_options)
      end
      options[:auth_logic] = fwd_connection
      run_loop_hook = -> { fwd_connection.process }
      fwd_connection.connect
      session = Net::SSH::Transport::ServerSession.new(client,options.merge(run_loop_hook:run_loop_hook))
      handler_added = false
      session.run_loop do |connection|
        if !handler_added
          fwd_connection.handle(connection)
          handler_added = true
        end
        fwd_connection.process
      end
    end
  end
end

sleep(1)
#Net::SSH.start('localhost', 'boga', port: PORT, password: "boga", verbose: :debug) do |ssh|
#  output = ssh.exec("hostname")
#end
sleep(160)
puts "END"

