#!/usr/bin/env ruby
require 'digest'
require 'json'
require 'time'

MAX_REPORT_BYTES = 262_144
IMAGE = 'quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa'
BUILD_IMAGE = 'rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922'
SCENARIOS = %w[bounded_cleanup expected_pools monitor_failover pool_map_updates secure_default_v2 wrong_fsid].freeze
TOP_KEYS = %w[bounds cluster command finished_at observations scenarios schema_version server source started_at status toolchain].freeze

def source_paths(root)
  paths = Dir.glob(File.join(root, 'src/**/*.rs')).map { |path| path.delete_prefix("#{root}/") }
  paths.concat(%w[Cargo.lock Cargo.toml build.rs rust-toolchain.toml integration/r05/live-report.schema.json integration/r05/live-reproduce.sh integration/r05/verify-live.rb integration/r05/verify-live-tests.sh])
  paths.sort
end

def exact_keys!(value, expected, label)
  raise "#{label} must be an object" unless value.is_a?(Hash)
  actual = value.keys.sort
  raise "#{label} keys #{actual.inspect}, want #{expected.sort.inspect}" unless actual == expected.sort
end

def sha256?(value)
  value.is_a?(String) && value.match?(/\A[0-9a-f]{64}\z/)
end

def pools!(probe, key, present: [], absent: [])
  pools = probe.fetch(key)
  raise "#{key} must contain unique strings" unless pools.is_a?(Array) && pools.all? { |item| item.is_a?(String) } && pools.uniq == pools
  present.each { |name| raise "#{key} lacks #{name}" unless pools.include?(name) }
  absent.each { |name| raise "#{key} contains #{name}" if pools.include?(name) }
end

root, report_path = ARGV
abort 'usage: verify-live.rb ROOT REPORT' unless root && report_path && ARGV.length == 2
root = File.expand_path(root)
data = File.binread(report_path, MAX_REPORT_BYTES + 1)
raise 'report exceeds size bound' if data.bytesize > MAX_REPORT_BYTES
report = JSON.parse(data)
exact_keys!(report, TOP_KEYS, 'report')
raise 'report identity is invalid' unless report['schema_version'] == 1 && report['status'] == 'passed' && report['command'] == 'integration/r05/live-reproduce.sh'
started = Time.iso8601(report.fetch('started_at'))
finished = Time.iso8601(report.fetch('finished_at'))
raise 'report timestamps are stale or reversed' unless started <= finished && finished - started <= 600

source = report.fetch('source')
exact_keys!(source, %w[artifacts identity], 'source')
raise 'source identity is invalid' unless source['identity'] == 'exact-content-addressed-artifacts'
artifacts = source.fetch('artifacts')
expected_paths = source_paths(root)
raise 'source artifact set mismatch' unless artifacts.keys.sort == expected_paths
expected_paths.each do |path|
  actual = artifacts.fetch(path)
  raise "invalid source hash for #{path}" unless sha256?(actual)
  expected = Digest::SHA256.file(File.join(root, path)).hexdigest
  raise "source hash mismatch for #{path}" unless actual == expected
end

server = report.fetch('server')
exact_keys!(server, %w[ceph_version image image_id platform], 'server')
raise 'server image is not pinned' unless server['image'] == IMAGE
raise 'server metadata is invalid' unless server['image_id'].to_s.match?(/\Asha256:[0-9a-f]{64}\z/) && %w[linux/amd64 linux/arm64].include?(server['platform']) && !server['ceph_version'].to_s.empty?
toolchain = report.fetch('toolchain')
exact_keys!(toolchain, %w[build_image build_image_id cargo probe_binary_path probe_binary_sha256 rustc], 'toolchain')
probe_binary = File.join(root, toolchain['probe_binary_path'].to_s)
raise 'toolchain is invalid' unless toolchain['rustc'].to_s.start_with?('rustc 1.98.0 ') && toolchain['cargo'].to_s.start_with?('cargo 1.98.0 ') && toolchain['build_image'] == BUILD_IMAGE && toolchain['build_image_id'] == 'sha256:85d3116eeb31c371bc51214ee0d7f4c5655d5b6f903d448fff4d1ed8af272fd2' && toolchain['probe_binary_path'] == 'target/r05/rados-r05-live' && File.file?(probe_binary) && toolchain['probe_binary_sha256'] == Digest::SHA256.file(probe_binary).hexdigest

cluster = report.fetch('cluster')
exact_keys!(cluster, %w[disposable_pool failover_pool fsid initial_pool monitors quorum_after_loss quorum_before seeds_used], 'cluster')
monitors = %w[v2:172.30.105.10:3300 v2:172.30.105.11:3300 v2:172.30.105.12:3300]
raise 'cluster identity or topology is invalid' unless cluster == {'fsid'=>'51111111-2222-4333-8444-555555555555','monitors'=>monitors,'seeds_used'=>monitors,'initial_pool'=>'r05-initial','disposable_pool'=>'r05-disposable','failover_pool'=>'r05-failover','quorum_before'=>3,'quorum_after_loss'=>2}
bounds = report.fetch('bounds')
exact_keys!(bounds, %w[command_seconds harness_seconds max_output_bytes max_report_bytes probe_seconds], 'bounds')
raise 'bounds are invalid' unless bounds == {'harness_seconds'=>600,'probe_seconds'=>120,'command_seconds'=>20,'max_output_bytes'=>65_536,'max_report_bytes'=>MAX_REPORT_BYTES}
scenarios = report.fetch('scenarios')
raise 'scenario key set mismatch' unless scenarios.keys.sort == SCENARIOS && scenarios.values.all? { |value| value == 'passed' }

observations = report.fetch('observations')
exact_keys!(observations, %w[cleanup probe wrong_fsid], 'observations')
probe = observations.fetch('probe')
exact_keys!(probe, %w[authenticated configured_security created_pools deleted_pools failover_pools fsid initial_pools instance_id schema_version], 'probe')
raise 'probe identity/authentication is invalid' unless probe['schema_version'] == 1 && probe['fsid'] == cluster['fsid'] && probe['instance_id'].is_a?(Integer) && probe['instance_id'].positive? && probe['configured_security'] == 'secure' && probe['authenticated'] == true
pools!(probe, 'initial_pools', present: ['r05-initial'], absent: ['r05-disposable', 'r05-failover'])
pools!(probe, 'created_pools', present: ['r05-initial', 'r05-disposable'])
pools!(probe, 'deleted_pools', present: ['r05-initial'], absent: ['r05-disposable'])
pools!(probe, 'failover_pools', present: ['r05-initial', 'r05-failover'], absent: ['r05-disposable'])
wrong = observations.fetch('wrong_fsid')
exact_keys!(wrong, %w[exit_code fsid_mismatch_observed stderr_sha256], 'wrong_fsid')
raise 'wrong FSID was not observed' unless wrong['exit_code'].is_a?(Integer) && wrong['exit_code'].positive? && wrong['fsid_mismatch_observed'] == true && sha256?(wrong['stderr_sha256'])
cleanup = observations.fetch('cleanup')
raise 'cleanup was not complete' unless cleanup == {'orphan_containers'=>0, 'orphan_networks'=>0}
puts 'R05 live report verification passed'