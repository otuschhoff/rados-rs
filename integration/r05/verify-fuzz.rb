#!/usr/bin/env ruby
require 'digest'
require 'json'
require 'open3'
require 'tmpdir'

TARGETS = %w[r05_config r05_monmap r05_osdmap r05_osdmap_incremental r05_monmap_message r05_osdmap_full_message r05_osdmap_incremental_message].freeze
SHA256 = /\A[0-9a-f]{64}\z/
TOP_KEYS = %w[bounds finding generated_at initial_corpus schema_version source status targets toolchain].freeze
RECORD_KEYS = %w[binary_path binary_sha256 command corpus_entries coverage features log_path log_sha256 name result runs].freeze

root, report_path = ARGV
abort 'usage: verify-fuzz.rb ROOT REPORT' unless root && report_path && ARGV.length == 2
root = File.expand_path(root)
raise 'report exceeds size bound' if File.size(report_path) > 262_144
report = JSON.parse(File.binread(report_path))
raise 'report key set mismatch' unless report.keys.sort == TOP_KEYS
raise 'invalid report identity' unless report['schema_version'] == 1 && report['status'] == 'passed'
raise 'invalid toolchain' unless report['toolchain'] == {'rustc'=>'rustc 1.100.0-nightly (0dfb098f3 2026-08-31)','cargo_fuzz'=>'cargo-fuzz 0.13.2','libfuzzer_sys'=>'0.4.13'}
raise 'invalid bounds' unless report['bounds'] == {'runs_per_target'=>2000,'max_len'=>33_554_432,'random_seed'=>505,'max_log_bytes'=>65_536}

paths = Dir.glob(File.join(root, 'src/**/*.rs')).map { |path| path.delete_prefix("#{root}/") }
paths.concat(Dir.glob(File.join(root, 'fuzz/fuzz_targets/r05_*.rs')).map { |path| path.delete_prefix("#{root}/") })
paths.concat(%w[Cargo.lock Cargo.toml build.rs rust-toolchain.toml fuzz/Cargo.lock fuzz/Cargo.toml integration/r05/fuzz-reproduce.sh integration/r05/prepare-fuzz-corpus.sh integration/r05/verify-fuzz.rb integration/r05/verify-fuzz-tests.sh])
paths.sort!
source = report.fetch('source')
raise 'source key set mismatch' unless source.keys.sort == %w[artifacts identity]
raise 'invalid source identity' unless source['identity'] == 'exact-content-addressed-artifacts'
artifacts = source.fetch('artifacts')
raise 'source artifact set mismatch' unless artifacts.keys.sort == paths
paths.each do |path|
  expected = Digest::SHA256.file(File.join(root, path)).hexdigest
  raise "source hash mismatch for #{path}" unless artifacts[path] == expected
end

records = report.fetch('targets')
raise 'target order mismatch' unless records.map { |record| record['name'] } == TARGETS
records.each do |record|
  name = record['name']
  raise "record key set mismatch for #{name}" unless record.keys.sort == RECORD_KEYS
  raise "invalid result for #{name}" unless record['runs'] == 2000 && record['result'] == 'passed'
  raise "invalid counters for #{name}" unless %w[coverage features corpus_entries].all? { |key| record[key].is_a?(Integer) && record[key].positive? }
  binary_path = record['binary_path']
  raise "binary path mismatch for #{name}" unless binary_path.match?(%r{\Afuzz/target/[^/]+/release/#{Regexp.escape(name)}\z})
  binary = File.join(root, binary_path)
  raise "binary is unavailable for #{name}" unless File.file?(binary)
  raise "binary hash mismatch for #{name}" unless record['binary_sha256'] == Digest::SHA256.file(binary).hexdigest
  expected_command = [name, "-artifact_prefix=fuzz/artifacts/#{name}/", '-seed=505', '-runs=2000', '-max_len=33554432', "CORPUS/#{name}"]
  raise "command mismatch for #{name}" unless record['command'] == expected_command
  log_path = record['log_path']
  raise "log path mismatch for #{name}" unless log_path == "docs/r05/fuzz-logs/#{name}.log"
  log = File.binread(File.join(root, log_path), 65_537)
  raise "log exceeds bound for #{name}" if log.bytesize > 65_536
  raise "log hash mismatch for #{name}" unless Digest::SHA256.hexdigest(log) == record['log_sha256']
  raise "completion record missing for #{name}" unless log.match?(/^#2000\s+DONE.*cov: #{record['coverage']} .*ft: #{record['features']} .*corp: #{record['corpus_entries']}\//)
end

Dir.mktmpdir('rados-r05-fuzz-verify') do |directory|
  preparer = File.join(root, 'integration/r05/prepare-fuzz-corpus.sh')
  raise 'corpus preparation failed' unless system('sh', preparer, directory, out: File::NULL)
  files = Dir.glob(File.join(directory, '**/*')).select { |path| File.file?(path) }.sort
  manifest = files.map { |path| "#{Digest::SHA256.file(path).hexdigest}  ./#{path.delete_prefix("#{directory}/")}" }.join("\n") + "\n"
  corpus = report.fetch('initial_corpus')
  raise 'corpus key set mismatch' unless corpus.keys.sort == %w[file_count sorted_manifest_sha256]
  raise 'corpus file count mismatch' unless corpus['file_count'] == files.length
  raise 'corpus manifest mismatch' unless corpus['sorted_manifest_sha256'] == Digest::SHA256.hexdigest(manifest)
end

puts 'R05 fuzz report verification passed'