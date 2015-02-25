require 'net/ssh'
require 'net/ssh/server'
require 'net/ssh/server/keys'
require 'net/ssh/transport/server_session'
require 'net/ssh/server/channel_extensions'
require 'socket'
require 'ostruct'

module Net ; module SSH ; module Server
  module ChannelExtensions
    EXTENDED_DATA_STDERR = 1
    def send_extended_data(data, type=EXTENDED_DATA_STDERR)
      msg = Net::SSH::Buffer.from(:byte, Net::SSH::Connection::Constants::CHANNEL_EXTENDED_DATA, 
        :long, remote_id, :long, type, :string, data)
      connection.send_message(msg)
    end
  end
end ; end ; end

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
    def server_filter
      @_server_filter
    end
    def server_filter=(value)
      @_server_filter=value
    end
  end

  def initialize(host,options)
    @host = host
    @options = options
    @event_loop = options[:event_loop]
    alogger = SSHFwd::_create_logger(options)
    alogger.formatter = proc { |severity, datetime, progname, msg| "[FWD] #{datetime}: #{msg}\n" }
    options[:logger] ||= alogger
    options[:ssh][:logger] = options[:logger]
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
    @auth = Net::SSH::Authentication::Session.new(@transport, @options[:ssh].merge(number_of_password_prompts: 0))
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
    channel.server_filter = filters[:server] if filters[:server]
  end

  def _handle_data_from_client(channel)
    channel.on_data do |channel,data|
      debug { "data from client -> server : #{_print_data(data)}" }

      if filter = channel.client_filter
        ret = filter.filterin(data)
        if ret
          if ret[:reply]
            puts ":reply is deprecated use :error_msg"
            channel.send_extended_data(ret[:reply])
            channel._flush
          end
          if ret[:error_msg]
            channel.send_extended_data(ret[:error_msg])
            channel._flush
          end
          if ret[:action] == :terminate
            raise Exception, "Bad command => terminate"
          end
        end
      end

      fwd_channel = _fwd_channel(channel)

      fwd_channel.send_data(data)
      fwd_channel._flush
    end
  end

  def _handle_data_from_server(channel)
    _fwd_channel(channel).on_data do |fwd_channel,data|
      debug { "data from server -> client : #{_print_data(data)}"}

      if filter = channel.server_filter
        ret = filter.filterout(data)
        if ret
          if ret[:reply]
            puts ":reply is deprecated use :error_msg"
            channel.send_extended_data(ret[:reply])
            channel._flush
          end
          if ret[:error_msg]
            channel.send_extended_data(ret[:error_msg])
            channel._flush
          end
          if ret[:action] == :terminate
            raise Exception, "Bad command => terminate"
          end
        end
      end

      channel.send_data(data)
      channel._flush
    end
  end

  def _handle_channel(channel)
    _supported_requests.each do |request_type|
      channel.on_request request_type do |channel,packet,options|
        debug { "request from client -> server: #{request_type}"}

        _setup_filters channel, @options[:create_filter][request_type,
            username:@username, packet:packet.remainder_as_buffer] if @options[:create_filter]

        _handle_data_from_server(channel)

        _handle_data_from_client(channel)

        if options[:want_reply]
          options[:want_reply] = false
          _fwd_channel(channel).send_channel_request(request_type,:raw,packet.read) do |fwd_ch, success|
            info { "received reply from server: #{request_type} #{success} forwarding to client" }
            channel.send_reply(success)
          end
        else
          _fwd_channel(channel).send_channel_request(request_type,:raw,packet.read)
        end

      end

      channel.on_eof do |channel|
        info { "received eof from client => forwarding to server" }
        _fwd_channel(channel).send_eof
      end
      channel.on_close do |channel|
        info { "received close from client => forwarding to server" }
        _fwd_channel(channel).close
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
      fwd_channel.on_request request_type do |fwd_channel,data,options|
        info { "received request from server #{request_type} so forwarding to client" }
        if options[:want_reply]
          options[:want_reply] = false
          channel.send_channel_request(request_type,:raw,data.read) do |fwd_ch, success|
            info { "received reply from client on #{request_type} #{success} forwarding to server" }
            channel.send_reply(success)
          end
        else
          channel.send_channel_request(request_type,:raw,data.read)
          channel._flush
        end
      end
    end
    fwd_channel.on_eof do |fwd_channel|
      #info { "received eof from server => closing channel to client" }
      #channel.send_eof_and_close
      info { "received eof from server => sending eof to client" }
      channel.send_eof
      info { "sent eof" }
    end
    fwd_channel.on_close do |fwd_channel|
      info { "received close from server => closing to client" }
      channel.close
      info { "sent close" }
    end
  end
end

class Server
  def initialize(server_options,forward_options)
    @server_options = server_options
    @forward_options = forward_options
    @stopped = false
  end

  def stop
    @stopped = true
    @port,@host = @server.addr[1..2]
    TCPSocket.new(@host,@port)
    @server.close
  end

  def handle_client(client,logger,evlogger,auth_logic,server_keys)
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
        options[:auth_methods] = ['gssapi-with-mic']
        options[:gss_server_host] = kerbotps[:host]
        options[:gss_server_service] = kerbotps[:service]
        options[:gss_server_servicekeytab] = kerbotps[:keytab]
      else
        options[:allowed_auth_methods] = ['password','none']
      end

      fwd_options = @forward_options
      fwd_options[:ssh]||={}
      fwd_options[:ssh][:listeners] = options[:listeners] if use_listeners
      fwd_options[:ssh][:event_loop] = event_loop unless use_listeners
      fwd_options[:ssh][:use_agent] = false
      if (kerbotps = @server_options[:kerberos])
        fwd_options[:ssh][:auth_methods] = ['gssapi-with-mic']
      else
        fwd_options[:ssh][:auth_methods] = ['keyboard-interactive','password']
      end
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
        fwd_connection.process
      end
    rescue Exception => exception
      logger.error { "Got exception: #{exception.inspect}" }
      logger.error { exception.backtrace.join("\n") }
      client.close
    end
  end

  def run
    unless logger = @server_options[:logger]
      logger = SSHFwd::_create_logger(@server_options)
    end

    logger.info { "Setting up server keys..." }
    server_keys = Net::SSH::Server::Keys.new(logger: logger, server_keys_directory: '.')
    server_keys.load_or_generate

    @server = @server_options[:server]

    if @server.nil?
      port = @server_options[:port]
      logger.info { "Listening on port #{port}..." }
      @server = TCPServer.new port
    end

    auth_logic = AuthLogic.new

    unless evlogger = @server_options[:logger] || @server_options[:evlogger]
      evlogger = SSHFwd::_create_logger(@server_options)
      evlogger.formatter = proc { |severity, datetime, progname, msg| "[EV] #{datetime}: #{msg}\n" }
    end

    loop do
      break if @stopped

      begin
        new_client = @server.accept
      rescue Errno::EBADF
        raise unless @stopped
      end

      Thread.start(new_client) do |client|
        handle_client(client,logger,evlogger,auth_logic,server_keys) unless @stopped
      end
    end
  end
end

end
