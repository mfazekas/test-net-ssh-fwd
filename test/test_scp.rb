require 'minitest/autorun'

require 'sshfwd/server'
require 'sshfwd/scpinputoutputfilter'

require 'socket'
require 'pty'
require 'expect'
require 'fileutils'

require 'ssh_fwd_base_test'

class ScpForwardTest < SshFwdBaseTest
  def test_scp_works
    start_server

    src_file = '/tmp/foo.txt'
    dst_file = '/tmp/foo.txt.cp'
    content = "tmp#{Time.now.to_i}"
    File.open(src_file, File::CREAT|File::TRUNC|File::RDWR, 0664) {|f| f.write(content) }

    ec,out = do_ssh(host:@host,port:@port,command:'scp',params:"#{src_file} #{user}@#{@host}:#{dst_file}")

    assert_equal(0,ec)
    assert_equal(content,File.open(dst_file,'r').read())
  end


  class TestScpFilter < ScpInputOutputFilter
    attr_accessor :filenames

    def handle_c_directive(line)
      filenames << line.split(' ')[2] if filenames
      if File.basename(line.split(' ')[2]) == 'secret.txt'
        {action: :terminate, error_msg: "BAD FILENAME\n"}
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

    ec,out = do_ssh(host:@host,port:@port,command:'scp',params:"#{src_file} #{src_file2} #{user}@#{@host}:/tmp/")

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
    ec,out = do_ssh(host:@host,port:@port,command:'scp',params:"#{src_file} #{user}@#{@host}:/tmp/dst/")

    assert_equal(1,ec)
    assert_equal(false,File.exists?(dst_file))
    assert_match(/BAD FILENAME/,out)
  end
end