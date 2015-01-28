ENABLE_KERBEROS =  ENV['NO_KRB'] ? false : true
$:.push(ENV['NET_SSH_DIR'] || './net-ssh/lib')
$:.push(ENV['GSSAPI_DIR'] || './gssapi/lib/') if ENABLE_KERBEROS
$:.push(ENV['NET_SSH_KERBEROS_DIR'] || './net-ssh-kerberos/lib/') if ENABLE_KERBEROS
$:.push("./lib")

require 'sshfwd/server'

class ClientInputFilter
  def initialize
    @buffer = ""
  end

  def filter(data)
    @buffer.concat(data)
    if @buffer =~ /shutdown/
      {action: :terminate, reply: "BAD"}
    else
      nil
    end
  end
end

server_options = {
  kerberos: {
    host: 'precise32.fazmic.com',
    service: 'host',
    keytab: '/etc/krb5.keytab'
  },
  verbose: (ENV['DEBUG'] && ENV['DEBUG'].include?('S')) ? :debug : :info,
  port: 2000
}
forward_options = {
  disabled: (ENV['NO_FORWARD']),
  host: 'localhost',
  verbose: (ENV['DEBUG'] && ENV['DEBUG'].include?('F')) ? :debug : :info,
  ssh: {
    port: 22
  },
  create_client_filter: ->(request_type) {
    case request_type 
      when 'pty-req'
        ClientInputFilter.new
      when 'shell'
        ClientInputFilter.new
      else
        nil
    end
  }
}

if ENV['NO_KRB']
  server_options.delete(:kerberos)
end

server = SSHFwd::Server.new(server_options,forward_options)
server.run
