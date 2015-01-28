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


module SSHFwd

def self._create_logger(options)
  logger = Logger.new(STDERR)
  logger.level = 
    case options[:verbose]
    when :debug
       Logger::DEBUG
    when :info
       Logger::INFO
    else
       Logger::WARN
    end
  logger
end

Thread.abort_on_exception=true

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
    def client_filter
      @_client_filter
    end
    def client_filter=(value)
      @_client_filter=value
    end
  end

  def initialize(host,options)
    @host = host
    @options = options
    alogger = SSHFwd::_create_logger(options)
    alogger.formatter = proc { |severity, datetime, progname, msg| "[FWD] #{datetime}: #{msg}\n" }
    options[:logger] = alogger
    self.logger = alogger
  end

  def connect
    @transport = Net::SSH::Transport::Session.new(@host, @options[:ssh])
    @transport.socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
  end

  def _init_connection
    @fwd_conn = Net::SSH::Connection::Session.new(@transport, @options[:ssh])
  end

  def allow_password?(username,password,options)
    @auth = Net::SSH::Authentication::Session.new(@transport, @options[:ssh])
    if @auth.authenticate(options[:next_service], username, password) 
      _init_connection
    end
  end

  def allow_kerberos?(username,srv,options)
    if delegated_credentials = srv.delegated_credentials
      @auth = Net::SSH::Authentication::Session.new(@transport, 
        @options[:ssh].merge(auth_methods: ["gssapi-with-mic"],
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

  def _handle_ptr_req(channel,data)
    term = data.read_string
    debug { "pty-req terminal: #{term}" }
  end

  def _handle_channel_request(channel,request_type,data)
    case request_type
    when 'pty-req'
      _handle_ptr_req(channel,data.remainder_as_buffer)
    end
  end

  def _print_data(data)
    out = data.to_s.each_byte.map do |ch|
      case ch 
      when 40..176
        "#{ch.chr}"
      else
        "\\x%02x" % ch
      end
    end.join("")
  end

  def _handle_channel(channel)
    _supported_requests.each do |request_type|
      channel.on_request request_type do |channel,data,options|
        channel.client_filter = @options[:create_client_filter][request_type]
        _handle_channel_request(channel,request_type,data)
        _fwd_channel(channel).on_data do |fwd_channel,data|
          debug { "data from fwd   -> : #{_print_data(data)}"}
          channel.send_data(data)
          channel._flush
        end
        channel.on_data do |channel,data|
          debug { "data from client -> : #{_print_data(data)}" }
          if filter = channel.client_filter
            ret = filter.filter(data)
            if ret
              if ret[:reply]
                channel.send_data(ret[:reply])
                channel._flush
              end
              if ret[:action] == :terminate
                raise Exception, "Bad command terminate"
              end
            end
          end
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

class Server
  def initialize(server_options,forward_options)
    @server_options = server_options
    @forward_options = forward_options
  end
  
  def run
    logger = SSHFwd::_create_logger(@server_options)
    logger.info { "Setting up server keys..." }
    server_keys = Net::SSH::Server::Keys.new(logger: logger, server_keys_directory: '.')
    server_keys.load_or_generate
    port = @server_options[:port]
    logger.info { "Listening on port #{port}..." }
    server = TCPServer.new port
    auth_logic = AuthLogic.new
    loop do
      Thread.start(server.accept) do |client|
        begin
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
          if (kerbotps = @server_options[:kerberos])
            options[:allowed_auth_methods] = ['gssapi-with-mic']
            options[:gss_server_host] = kerbotps[:host]
            options[:gss_server_service] = kerbotps[:service]
            options[:gss_server_servicekeytab] = kerbotps[:keytab]
          end

          fwd_options = @forward_options
          fwd_options[:ssh]||={}
          fwd_options[:ssh][:listeners] = options[:listeners]
          fwd_host = @forward_options[:host]

          fwd_connection = FwdConnection.new(fwd_host,fwd_options)
          if @forward_options[:disabled]
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
        rescue Exception => exception
          logger.error { "Got exception: #{exception.inspect}" }
          logger.error { exception.backtrace }
          client.close
        end
      end
    end    
  end
end

end