require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs << "lib"
  t.libs << "net-ssh/lib"
  t.libs << "net-ssh-kerberos/lib"
  t.libs << "gssapi/lib"
  t.libs << "test"
  t.test_files = FileList['test/test*.rb']
end