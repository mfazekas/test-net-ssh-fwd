require 'minitest/autorun'

require 'sshfwd/server'
require 'sshfwd/scpinputoutputfilter'

require 'socket'
require 'pty'
require 'expect'
require 'fileutils'

require 'ssh_fwd_base_test'
require 'net/ssh/kerberos'

class ScpForwardTest < SshFwdBaseTest
  def test_scp_works_with_kerberos
    start_server({kerberos: {
      host: 'precise32.fazmic.com',
      service: 'host',
      keytab: '/etc/krb5.keytab'
    }})
    system("yes 'pwd' | kinit fazmic@FAZMIC.COM")
    @host = 'precise32.fazmic.com'

    FileUtils::mkdir_p "/tmp/src", mode: 0770
    FileUtils::mkdir_p "/tmp/dst", mode: 0770
    src_file = '/tmp/src/foo.txt'
    dst_file = '/tmp/dst/foo.txt.krb'
    content = "tmp#{Time.now.to_i}"
    File.open(src_file, File::CREAT|File::TRUNC|File::RDWR, 0664) {|f| f.write(content) }

    user = 'fazmic'
    ec,out = do_ssh(host:@host,port:@port,command:'scp',params:"#{src_file} #{user}@#{@host}:#{dst_file}",
          sshopts: {GSSAPIAuthentication: 'yes', GSSAPIDelegateCredentials: 'yes'})

    assert_equal(0,ec)
    assert_equal(content,File.open(dst_file,'r').read())
  end
end