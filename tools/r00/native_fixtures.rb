require 'json'
require 'digest'
require 'open3'
require 'tmpdir'
require 'time'

root = File.expand_path('../..', __dir__)
destination = File.join(root, 'docs/r00/native-fixtures.json')
abort 'Native report already exists; preserve it before an explicit rerun' if File.exist?(destination)
baseline = JSON.parse(File.read(File.join(root, 'reference/go-baseline.json')))
archive = File.join(root, baseline.fetch('archive'))
abort 'Archive hash mismatch' unless Digest::SHA256.file(archive).hexdigest == baseline.fetch('archive_sha256')
report = { schema_version: 1, started_at: Time.now.utc.iso8601, archive_sha256: baseline.fetch('archive_sha256'), cases: [] }
Dir.mktmpdir('rados-rs-native-') do |directory|
  output, result = Open3.capture2e('tar', '-xzf', archive, '-C', directory)
  abort "Archive extraction failed: #{output}" unless result.success?
  Dir[File.join(root, 'testdata/p01/*.bin.json')].sort.each do |filename|
    manifest = JSON.parse(File.read(filename))
    arguments = manifest.fetch('generator').fetch('command').map do |argument|
      argument == '$PWD:/src:ro' ? "#{directory}:/src:ro" : argument
    end
    abort 'Unresolved shell substitution' if arguments.any? { |argument| argument.include?('$') }
    payload, errors, result = Open3.capture3(*arguments)
    actual = Digest::SHA256.hexdigest(payload)
    report[:cases] << { fixture: manifest.fetch('fixture'), argv: arguments, exit_code: result.exitstatus, stderr: errors, expected_sha256: manifest.fetch('sha256'), observed_sha256: actual, pass: result.success? && actual == manifest.fetch('sha256') }
  end
end
report[:completed_at] = Time.now.utc.iso8601
report[:pass] = report[:cases].length == 6 && report[:cases].all? { |entry| entry[:pass] }
File.write(destination, JSON.pretty_generate(report) + "\n")
puts "Native P01 parity: #{report[:cases].count { |entry| entry[:pass] }}/#{report[:cases].length} cases passed"
exit 1 unless report[:pass]