require 'json'
require 'open-uri'
require 'open3'
require 'time'
require 'digest'

root = File.expand_path('../..', __dir__)
destination = File.join(root, 'docs/r00/observations.json')
abort 'Observation file already exists; preserve it and review a new observation explicitly' if File.exist?(destination)
report = { schema_version: 1, observed_at: Time.now.utc.iso8601, commands: [], crates: [] }
commands = [
  %w[rustc -Vv], %w[cargo -V], %w[rustup show], %w[go version],
  ['docker', 'version', '--format', '{{.Server.Version}}'],
  ['docker', 'info', '--format', '{{json .NCPU}} {{json .MemTotal}}'],
  ['df', '-h', root],
  ['gh', 'api', 'repos/ceph/ceph/git/commits/69f84cc2651aa259a15bc192ddaabd3baba07489', '--jq', '.sha'],
  ['gh', 'api', 'repos/ceph/ceph/git/commits/7f793731f1b39eb4f465e960113d2363c311b964', '--jq', '.sha']
]
pins = JSON.parse(File.read(File.join(root, 'reference/go/docs/p00/evidence.json')))
%w[baseline qualification].each do |profile|
  commands << ['docker', 'buildx', 'imagetools', 'inspect', pins.fetch('images').fetch(profile).fetch('reference'), '--raw']
end
commands.each do |arguments|
  output, result = Open3.capture2e(*arguments, chdir: root)
  report[:commands] << { argv: arguments, exit_code: result.exitstatus, output: output, output_sha256: Digest::SHA256.hexdigest(output) }
end
headers = { 'User-Agent' => 'rados-rs-r00-evidence/0.1' }
%w[rados-rs tokio bytes thiserror aes aes-gcm cbc hmac sha2 zeroize secrecy getrandom serde serde_json base64 tracing kerberos_crypto].each do |name|
  url = "https://crates.io/api/v1/crates/#{name}"
  begin
    raw = URI.open(url, headers.merge(open_timeout: 20, read_timeout: 30)).read
    data = JSON.parse(raw)
    version = data.fetch('versions').find { |row| !row['yanked'] && row['num'] == data.fetch('crate').fetch('max_stable_version') }
    report[:crates] << { name: name, url: url, http_status: 200, response_sha256: Digest::SHA256.hexdigest(raw), version: version&.fetch('num'), rust_version: version&.fetch('rust_version', nil), license: version&.fetch('license'), updated_at: data.fetch('crate').fetch('updated_at'), interpretation: 'Registry metadata only; no compilation, security audit, reservation or feature-resolution claim' }
  rescue OpenURI::HTTPError => error
    report[:crates] << { name: name, url: url, http_status: error.io.status.first.to_i, error: error.message }
  rescue StandardError => error
    report[:crates] << { name: name, url: url, error: error.message }
  end
end
report[:completed_at] = Time.now.utc.iso8601
File.write(destination, JSON.pretty_generate(report) + "\n")
failed_commands = report[:commands].count { |entry| entry[:exit_code] != 0 }
failed_queries = report[:crates].count { |entry| entry[:http_status] != 200 && !(entry[:name] == 'rados-rs' && entry[:http_status] == 404) }
puts "Recorded #{report[:commands].length} commands and #{report[:crates].length} registry checks; #{failed_commands} command failures, #{failed_queries} unexpected query failures"
exit 1 if failed_commands != 0 || failed_queries != 0