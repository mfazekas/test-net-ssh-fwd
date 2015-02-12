ENABLE_KERBEROS =  ENV['NO_KRB'] ? false : true
$:.push(ENV['NET_SSH_DIR'] || './net-ssh/lib')
$:.push(ENV['GSSAPI_DIR'] || './gssapi/lib/') if ENABLE_KERBEROS
$:.push(ENV['NET_SSH_KERBEROS_DIR'] || './net-ssh-kerberos/lib/') if ENABLE_KERBEROS
$:.push(ENV['BELTONE_DIR'] || './beltone/lib')
$:.push("./lib")

if ENABLE_KERBEROS
require 'net/ssh/kerberos'
end

require 'sshfwd/server'
require 'screen'
require 'parser'

class ClientInputFilter
  def initialize
    @buffer = ""
  end

  def filterin(data)
    @buffer.concat(data)
    if @buffer =~ /shutdown/
      {action: :terminate, error_msg: "BAD FILENAME\n"}
    else
      nil
    end
  end
end

class ClientOutputFilter
  def initialize(terminal,w,h)
    @screen = Screen.new(width:w,height:h)
    @parser = Parser.new(@screen)
  end

  def filterout(data)
    @parser.read_tokens(data)
    if @screen.line(@screen.cursor_y) =~ /shutdown/
      {action: :terminate, error_msg: "BAD COMMAND\n"}
    else
      nil
    end
  end
end

LISTEN_PORT = 2000
DEST_PORT = 22

server_options = {
  kerberos: {
    host: 'precise32.fazmic.com',
    service: 'host',
    keytab: '/etc/krb5.keytab'
  },
  verbose: (ENV['DEBUG'] && ENV['DEBUG'].include?('S')) ? :debug : :warn,
  port: LISTEN_PORT
}
forward_options = {
  disabled: (ENV['NO_FORWARD']),
  host: 'localhost',
  verbose: (ENV['DEBUG'] && ENV['DEBUG'].include?('F')) ? :debug : :warn,
  ssh: {
    port: DEST_PORT
  },
  create_filter: ->(request_type, options = {}) {
    puts " => user #{options[:username]} request_type:#{request_type}"
    case request_type
      when 'pty-req'
        terminal = options[:packet].read_string
        width = options[:packet].read_long
        height = options[:packet].read_long
        puts "terminal: #{terminal}"
        {client:ClientInputFilter.new, server:ClientOutputFilter.new(terminal,width,height)}
      when 'shell'
        {client:ClientInputFilter.new}
      when 'exec'
        command = options[:packet].read_string
        puts "exec: #{command}"
        nil
      else
        puts "unknown: #{request_type}"
        nil
    end
  }
}

if ENV['NO_KRB']
  server_options.delete(:kerberos)
end

server = SSHFwd::Server.new(server_options,forward_options)
server.run
