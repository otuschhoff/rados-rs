#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <vector>

#include <rados/librados.hpp>

namespace {
constexpr std::size_t payload_bytes = 4096;
constexpr std::size_t operations = 128;

void check(int result, const char* operation) {
  if (result < 0) {
    throw std::runtime_error(std::string(operation) + ": " + std::strerror(-result));
  }
}

std::string argument(int argc, char** argv, const std::string& name) {
  for (int index = 1; index + 1 < argc; index += 2) {
    if (argv[index] == name) {
      return argv[index + 1];
    }
  }
  throw std::runtime_error("missing " + name);
}

std::string read_all(librados::IoCtx& io, const std::string& object) {
  librados::bufferlist data;
  const int length = io.read(object, data, 1 << 20, 0);
  check(length, "read");
  return data.to_str();
}

void require_contents(librados::IoCtx& io, const std::string& object, const std::string& expected) {
  if (read_all(io, object) != expected) {
    throw std::runtime_error("content mismatch for " + object);
  }
}

librados::bufferlist bytes(const std::string& value) {
  librados::bufferlist result;
  result.append(value);
  return result;
}

std::string read_key(const std::string& path) {
  std::ifstream input(path);
  std::string value;
  input >> value;
  if (!input || value.empty()) {
    throw std::runtime_error("cannot read key file");
  }
  return value;
}

double timeval_seconds(const timeval& value) {
  return static_cast<double>(value.tv_sec) + static_cast<double>(value.tv_usec) / 1000000.0;
}

double percentile(const std::vector<double>& values, std::size_t percent) {
  return values[(values.size() - 1) * percent / 100];
}

void run_suite(librados::IoCtx& io) {
  const std::string object = "native-mutations";
  io.remove(object);
  check(io.create(object, true), "create");
  auto initial = bytes("abcdef");
  check(io.write(object, initial, initial.length(), 0), "write");
  require_contents(io, object, "abcdef");
  auto full = bytes("0123456789");
  check(io.write_full(object, full), "write_full");
  auto suffix = bytes("AB");
  check(io.append(object, suffix, suffix.length()), "append");
  require_contents(io, object, "0123456789AB");
  check(io.trunc(object, 8), "truncate");
  librados::ObjectWriteOperation zero;
  zero.zero(2, 3);
  check(io.operate(object, &zero), "zero");
  require_contents(io, object, std::string({'0', '1', '\0', '\0', '\0', '5', '6', '7'}));
  check(io.remove(object), "remove");
  librados::bufferlist missing;
  if (io.read(object, missing, 1, 0) != -ENOENT) {
    throw std::runtime_error("remove was not visible");
  }

  std::string payload(payload_bytes, '\0');
  for (std::size_t index = 0; index < payload.size(); ++index) {
    payload[index] = static_cast<char>(index);
  }
  auto payload_list = bytes(payload);
  check(io.write_full("native-performance", payload_list), "performance warmup");
  rusage before{};
  rusage after{};
  check(getrusage(RUSAGE_SELF, &before), "getrusage before");
  std::vector<double> latencies;
  latencies.reserve(operations);
  const auto started = std::chrono::steady_clock::now();
  for (std::size_t index = 0; index < operations; ++index) {
    const auto operation_started = std::chrono::steady_clock::now();
    check(io.write_full("native-performance", payload_list), "performance write_full");
    const auto duration = std::chrono::steady_clock::now() - operation_started;
    latencies.push_back(std::chrono::duration<double, std::micro>(duration).count());
  }
  const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  check(getrusage(RUSAGE_SELF, &after), "getrusage after");
  std::sort(latencies.begin(), latencies.end());
  const auto retained = payload.capacity();
  std::cout << "{\"create\":true,\"write\":true,\"write_full\":true,\"append\":true,\"truncate\":true,\"zero\":true,\"remove\":true,"
            << "\"performance\":{"
            << "\"implementation\":\"native\",\"workload\":\"write-full-baseline-v1\",\"payload_bytes\":" << payload_bytes
            << ",\"concurrency\":1,\"operations\":" << operations << ",\"elapsed_seconds\":" << elapsed
            << ",\"operations_per_second\":" << static_cast<double>(operations) / elapsed
            << ",\"latency_p50_microseconds\":" << percentile(latencies, 50)
            << ",\"latency_p95_microseconds\":" << percentile(latencies, 95)
            << ",\"latency_p99_microseconds\":" << percentile(latencies, 99)
            << ",\"cpu_user_seconds\":" << timeval_seconds(after.ru_utime) - timeval_seconds(before.ru_utime)
            << ",\"cpu_system_seconds\":" << timeval_seconds(after.ru_stime) - timeval_seconds(before.ru_stime)
            << ",\"allocation_metric\":{\"name\":\"probe_payload_buffer_allocations\",\"value\":1}"
            << ",\"retained_bytes\":" << retained << ",\"peak_rss_bytes\":" << static_cast<std::uint64_t>(after.ru_maxrss) * 1024 << "}}\n";
}
}  // namespace

int main(int argc, char** argv) {
  try {
    const std::string action = argument(argc, argv, "--action");
    const std::string monitors = argument(argc, argv, "--monitors");
    const std::string key = read_key(argument(argc, argv, "--key"));
    const std::string fsid = argument(argc, argv, "--fsid");
    librados::Rados cluster;
    check(cluster.init2("client.r08", "ceph", 0), "init2");
    check(cluster.conf_set("mon_host", monitors.c_str()), "set monitors");
    check(cluster.conf_set("key", key.c_str()), "set key");
    check(cluster.conf_set("fsid", fsid.c_str()), "set fsid");
    check(cluster.connect(), "connect");
    librados::IoCtx io;
    check(cluster.ioctx_create("r08-data", io), "open pool");
    if (action == "suite") {
      run_suite(io);
    } else if (action == "cross-require-write") {
      require_contents(io, "cross-client", argument(argc, argv, "--expect"));
      auto value = bytes(argument(argc, argv, "--value"));
      check(io.write_full("cross-client", value), "cross-client write_full");
    } else {
      throw std::runtime_error("unsupported action " + action);
    }
    io.close();
    cluster.shutdown();
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "r08 native probe: " << error.what() << '\n';
    return 1;
  }
}