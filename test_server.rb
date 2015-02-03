# server for debugging listens on port 2700
$:.push(ENV['NET_SSH_DIR'] || './net-ssh/lib')
require 'net/ssh'
require 'net/ssh/server'
require 'net/ssh/server/keys'
require 'net/ssh/transport/server_session'
require 'net/ssh/server/channel_extensions'
require 'byebug'
require 'socket'

PORT = 2700

class AuthLogic
  def allow_password?(username,password,options)
    true
  end

  def allow_none?(username,options)
    true
  end
end

def _create_logger(options)
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

class Server
  def initialize(server_options)
    @server_options = server_options
  end

  def _supported_requests
    ['shell','exec','pty-req','env']
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
        if options[:want_reply]
          channel.send_reply(true)
          options[:want_reply] = false
          channel.send_data("In echo mode:")
          channel._flush
        end
        puts "got request: #{request_type}"
        channel.on_data do |channel,data|
          puts "cli->srv:#{_print_data(data)}"
          puts "echoing back"
          channel.send_data(data.to_s)
          channel._flush
        end
      end
    end
  end
  
  def run
    logger = _create_logger(@server_options)
    logger.info { "Setting up server keys..." }
    server_keys = Net::SSH::Server::Keys.new(logger: logger, server_keys_directory: '.')
    server_keys.load_or_generate
    port = @server_options[:port]
    logger.info { "Listening on port #{port}..." }
    server = TCPServer.new port
    auth_logic = AuthLogic.new

    evlogger = _create_logger(@server_options)
    evlogger.formatter = proc { |severity, datetime, progname, msg| "[EV] #{datetime}: #{msg}\n" }
    loop do
      Thread.start(server.accept) do |client|
        begin
          event_loop = Net::SSH::Connection::Session::EventLoop.new(evlogger)
          client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          options = {}
          use_ev = false
          options[:logger] = logger
          options[:server_side] = true
          options[:server_keys] = server_keys.keys
          options[:host_key] = server_keys.types
          options[:kex] = ['diffie-hellman-group-exchange-sha256']
          options[:hmac] = ['hmac-md5']
          options[:auth_logic] = auth_logic
          options[:event_loop] = event_loop if use_ev
          session = Net::SSH::Transport::ServerSession.new(client,options)

          handler_added = false
          session.run_loop do |connection|
            if !handler_added
              connection.on_open_channel('session') do |session, channel, packet|
                channel.extend(Net::SSH::Server::ChannelExtensions)
                _handle_channel(channel)
                logger.debug { "received open_channel from client" }
              end
              handler_added = true
            end
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

server_options = {
  verbose: (ENV['DEBUG'] && ENV['DEBUG'].include?('S')) ? :debug : :info,
  port: PORT
}

puts "PORT is #{PORT}"

server = Server.new(server_options)
server.run