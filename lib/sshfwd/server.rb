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
    @event_loop = options[:event_loop]
    alogger = SSHFwd::_create_logger(options)
    alogger.formatter = proc { |severity, datetime, progname, msg| "[FWD] #{datetime}: #{msg}\n" }
    options[:logger] = alogger
    options[:ssh][:logger] = alogger
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
      @username = username
    end
  end

  def allow_kerberos?(username,srv,options)
    if delegated_credentials = srv.delegated_credentials
      @auth = Net::SSH::Authentication::Session.new(
        @transport, 
        @options[:ssh].merge(
          auth_methods: ["gssapi-with-mic"],
          gss_delegated_credentials: delegated_credentials))
      debug { "_auth started to upstream " }
      if @auth.authenticate(options[:next_service], username)
        debug { "_auth finished to upstream" }
        _init_connection
        @username = username
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
    ['shell','exec','pty-req','env','subsystem']
  end

  # wait for the channel to become available
  # we should not process our channels
  # as we're not that reetrant
  def _fwd_channel(channel)
    result = channel.fwd_channel
    while result.nil? do
      timeout = 0.001
      debug { "waiting for fwd hannel "}
      if @event_loop
        @event_loop.process_only(@fwd_conn,timeout)
      else
        @fwd_conn.process(timeout)
      end
      result = channel.fwd_channel
    end
    return result
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

  def _setup_filters channel, filters
    return if filters.nil?
    channel.client_filter = filters[:client] if filters[:client]
  end

  def _handle_data_from_client(channel)
    channel.on_data do |channel,data|
      debug { "data from client -> server : #{_print_data(data)}" }

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
  end

  def _handle_channel(channel)
    _supported_requests.each do |request_type|
      channel.on_request request_type do |channel,packet,options|
        debug { "request from client -> server: #{request_type}"}
        _setup_filters channel, @options[:create_filter][request_type,
            username:@username, packet:packet.remainder_as_buffer]

        _fwd_channel(channel).on_data do |fwd_channel,data|
          debug { "data from server -> client : #{_print_data(data)}"}
          channel.send_data(data)
          channel._flush
        end

        _handle_data_from_client(channel)

        if options[:want_reply]
          _fwd_channel(channel).send_channel_request(request_type,:raw,packet.read) do |fwd_ch, success|
            info { "received reply from server: #{request_type} #{success} forwarding to client" }
            channel.send_reply(success)
            options[:want_reply] = false
          end
        else
          _fwd_channel(channel).send_channel_request(request_type,:raw,packet.read)
        end

      end

      channel.on_eof do |channel|
        info { "received eof from client => closing channel to server" }
        _fwd_channel(channel).eof!
        _fwd_channel(channel)._flush
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
        fwd_channel.extend(Net::SSH::Server::ChannelExtensions)
        channel.fwd_channel = fwd_channel
        register_server_request_handlers(fwd_channel,channel)
      end
      debug { "reply open_channel session to client" }
    end
  end

  def forward_request_client_server
    ["exit-status"]
  end

  def register_server_request_handlers(fwd_channel,channel)
    forward_request_client_server.each do |request_type|
      fwd_channel.on_request request_type do |channel,data,options|
        info { "received request from server #{request_type} so forwarding to client" }
        if options[:want_reply]
          channel.send_channel_request(request_type,:raw,data.read) do |fwd_ch, success|
            info { "received reply from client on #{request_type} #{success} forwarding to server" }
            channel.send_reply(success)
            options[:want_reply] = false
          end
        else
          channel.send_channel_request(request_type,:raw,data.read)
        end
      end
    end
    fwd_channel.on_eof do |fwd_channel|
      info { "received eof from server => closing channel to client" }
      channel.send_eof_and_close
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

    evlogger = SSHFwd::_create_logger(@server_options)
    evlogger.formatter = proc { |severity, datetime, progname, msg| "[EV] #{datetime}: #{msg}\n" }
    loop do
      Thread.start(server.accept) do |client|
        begin
          event_loop = Net::SSH::Connection::Session::EventLoop.new(evlogger)
          client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          options = {}
          use_listeners = false
          options[:listeners] ={} if use_listeners
          options[:logger] = logger
          options[:server_side] = true
          options[:server_keys] = server_keys.keys
          options[:host_key] = server_keys.types
          options[:kex] = ['diffie-hellman-group-exchange-sha256']
          options[:hmac] = ['hmac-md5']
          options[:auth_logic] = auth_logic
          options[:event_loop] = event_loop unless use_listeners
          if (kerbotps = @server_options[:kerberos])
            options[:allowed_auth_methods] = ['gssapi-with-mic']
            options[:gss_server_host] = kerbotps[:host]
            options[:gss_server_service] = kerbotps[:service]
            options[:gss_server_servicekeytab] = kerbotps[:keytab]
          end

          fwd_options = @forward_options
          fwd_options[:ssh]||={}
          fwd_options[:ssh][:listeners] = options[:listeners] if use_listeners
          fwd_options[:ssh][:event_loop] = event_loop unless use_listeners
          fwd_options[:event_loop] = event_loop unless use_listeners
          fwd_options[:ssh][:verbose] = @forward_options[:verbose] if @forward_options[:verbose]
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
            #if use_listeners
              fwd_connection.process
              #else
            #  event_loop.process
            #end
          end
        rescue Exception => exception
          logger.error { "Got exception: #{exception.inspect}" }
          logger.error { exception.backtrace.join("\n") }
          client.close
        end
      end
    end    
  end
end

end