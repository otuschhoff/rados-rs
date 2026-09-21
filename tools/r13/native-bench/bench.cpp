// R13 native benchmark: implements the frozen 4x3x3 matrix (sizes 4KiB,
// 64KiB, 1MiB, 4MiB × concurrencies 1/16/64 × workloads read/write/mixed)
// against a live Ceph cluster and emits a schema-valid benchmark_run JSON
// document on stdout. Uses only public librados C++ APIs.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <vector>

#include <rados/librados.hpp>

namespace {
constexpr std::size_t sizes[] = {4096, 65536, 1048576, 4194304};
constexpr std::uint32_t concurrencies[] = {1, 16, 64};
constexpr const char* workloads[] = {"read", "write", "mixed"};

std::string argument(int argc, char** argv, const std::string& name) {
  for (int index = 1; index + 1 < argc; index += 2) {
    if (argv[index] == name) {
      return argv[index + 1];
    }
  }
  throw std::runtime_error("missing " + name);
}

std::string read_key(const std::string& path) {
  std::ifstream input(path);
  std::string value;
  input >> value;
  if (!input || value.empty()) {
    throw std::runtime_error("cannot read key file " + path);
  }
  return value;
}

void check(int result, const char* operation) {
  if (result < 0) {
    throw std::runtime_error(std::string(operation) + ": " + std::strerror(-result));
  }
}

librados::bufferlist seeded_payload(std::size_t size, std::uint64_t seed) {
  std::string data(size, '\0');
  for (std::size_t index = 0; index < size; ++index) {
    data[index] = static_cast<char>((seed + index) & 0xff);
  }
  librados::bufferlist buffer;
  buffer.append(data);
  return buffer;
}

std::uint64_t percentile_ns(std::vector<std::uint64_t>& values, std::size_t percentile) {
  if (values.empty()) return 0;
  std::sort(values.begin(), values.end());
  const std::size_t index = (values.size() - 1) * percentile / 100;
  return values[index];
}

std::uint64_t peak_rss_bytes() {
  rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) != 0) return 1;
  // ru_maxrss is in kilobytes on Linux.
  return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024;
}

std::uint64_t cpu_ns(const timeval& tv) {
  return static_cast<std::uint64_t>(tv.tv_sec) * 1'000'000'000ull +
         static_cast<std::uint64_t>(tv.tv_usec) * 1'000ull;
}

struct Row {
  std::size_t size_bytes;
  std::uint32_t concurrency;
  std::string workload;
  std::uint64_t operations;
  std::uint64_t bytes;
  std::uint64_t elapsed_ns;
  double throughput;
  double iops;
  std::uint64_t p50_ns;
  std::uint64_t p95_ns;
  std::uint64_t p99_ns;
};

Row run_row(librados::IoCtx& io,
            const std::string& transport,
            std::size_t size,
            std::uint32_t concurrency,
            const std::string& workload) {
  const std::uint64_t operations = static_cast<std::uint64_t>(concurrency) * 2;
  const librados::bufferlist payload = seeded_payload(size, concurrency);

  std::vector<std::string> objects;
  objects.reserve(concurrency);
  for (std::uint32_t worker = 0; worker < concurrency; ++worker) {
    std::ostringstream name;
    name << "bench-" << transport << "-" << size << "-c" << concurrency << "-"
         << workload << "-" << std::setw(4) << std::setfill('0') << worker;
    const std::string object = name.str();
    io.remove(object);
    if (workload == "read" || workload == "mixed") {
      auto local = payload;
      check(io.write_full(object, local), "prewrite");
    }
    objects.push_back(object);
  }

  std::vector<std::uint64_t> latencies(operations, 0);
  std::mutex latency_mutex;
  std::vector<std::thread> workers;
  std::atomic<bool> error{false};
  std::string error_message;
  std::mutex error_mutex;

  const auto started = std::chrono::steady_clock::now();
  for (std::uint32_t worker = 0; worker < concurrency; ++worker) {
    const std::string object = objects[worker];
    workers.emplace_back([&, object, worker]() {
      try {
        for (std::uint32_t iteration = 0; iteration < 2; ++iteration) {
          const auto op_start = std::chrono::steady_clock::now();
          if (workload == "write") {
            auto local = payload;
            check(io.write_full(object, local), "write_full");
          } else if (workload == "read") {
            librados::bufferlist reply;
            const int length = io.read(object, reply, payload.length(), 0);
            check(length, "read");
            if (static_cast<std::size_t>(length) != payload.length()) {
              throw std::runtime_error("bench read short");
            }
          } else if (workload == "mixed") {
            if (iteration % 2 == 0) {
              auto local = payload;
              check(io.write_full(object, local), "mixed write_full");
            } else {
              librados::bufferlist reply;
              const int length = io.read(object, reply, payload.length(), 0);
              check(length, "mixed read");
            }
          } else {
            throw std::runtime_error("unknown workload");
          }
          const auto latency = std::chrono::steady_clock::now() - op_start;
          const auto latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(latency).count();
          std::lock_guard<std::mutex> guard(latency_mutex);
          latencies[worker * 2 + iteration] = static_cast<std::uint64_t>(latency_ns);
        }
      } catch (const std::exception& exception) {
        std::lock_guard<std::mutex> guard(error_mutex);
        if (!error.exchange(true)) {
          error_message = exception.what();
        }
      }
    });
  }
  for (auto& worker : workers) worker.join();
  if (error) throw std::runtime_error(error_message);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  const std::uint64_t elapsed_ns =
      std::max<std::uint64_t>(1, std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());

  for (const auto& object : objects) io.remove(object);

  const std::uint64_t bytes_total = static_cast<std::uint64_t>(size) * operations;
  Row row{};
  row.size_bytes = size;
  row.concurrency = concurrency;
  row.workload = workload;
  row.operations = operations;
  row.bytes = bytes_total;
  row.elapsed_ns = elapsed_ns;
  row.throughput = static_cast<double>(bytes_total) * 1e9 / static_cast<double>(elapsed_ns);
  row.iops = static_cast<double>(operations) * 1e9 / static_cast<double>(elapsed_ns);
  row.p50_ns = std::max<std::uint64_t>(1, percentile_ns(latencies, 50));
  row.p95_ns = std::max<std::uint64_t>(1, percentile_ns(latencies, 95));
  row.p99_ns = std::max<std::uint64_t>(1, percentile_ns(latencies, 99));
  return row;
}

void emit_json(const std::string& transport,
               const std::vector<Row>& rows,
               std::uint64_t cpu_user_ns_delta,
               std::uint64_t cpu_system_ns_delta) {
  std::cout << "{";
  std::cout << "\"implementation\":\"native\",";
  std::cout << "\"transport\":\"" << transport << "\",";
  std::cout << "\"environment\":{";
  std::cout << "\"os\":\"linux\",";
  std::cout << "\"arch\":\"" <<
#if defined(__aarch64__)
      "aarch64"
#elif defined(__x86_64__)
      "x86_64"
#else
      "unknown"
#endif
      << "\",";
  std::cout << "\"runtime\":\"librados-cpp\"";
  std::cout << "},";
  std::cout << "\"resources\":{";
  std::cout << "\"cpu_user_ns\":" << cpu_user_ns_delta << ",";
  std::cout << "\"cpu_system_ns\":" << cpu_system_ns_delta << ",";
  std::cout << "\"allocations\":null,";
  std::cout << "\"allocated_bytes\":null,";
  std::cout << "\"max_rss_bytes\":" << std::max<std::uint64_t>(1, peak_rss_bytes());
  std::cout << "},";
  std::cout << "\"rows\":[";
  for (std::size_t index = 0; index < rows.size(); ++index) {
    const Row& row = rows[index];
    if (index > 0) std::cout << ",";
    std::cout << "{";
    std::cout << "\"size_bytes\":" << row.size_bytes << ",";
    std::cout << "\"concurrency\":" << row.concurrency << ",";
    std::cout << "\"workload\":\"" << row.workload << "\",";
    std::cout << "\"operations\":" << row.operations << ",";
    std::cout << "\"bytes\":" << row.bytes << ",";
    std::cout << "\"elapsed_ns\":" << row.elapsed_ns << ",";
    std::cout.precision(17);
    std::cout << "\"throughput_bytes_per_second\":" << row.throughput << ",";
    std::cout << "\"iops\":" << row.iops << ",";
    std::cout << "\"p50_ns\":" << row.p50_ns << ",";
    std::cout << "\"p95_ns\":" << row.p95_ns << ",";
    std::cout << "\"p99_ns\":" << row.p99_ns;
    std::cout << "}";
  }
  std::cout << "]}" << std::endl;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    const std::string monitors = argument(argc, argv, "--monitors");
    const std::string fsid = argument(argc, argv, "--fsid");
    const std::string pool = argument(argc, argv, "--pool");
    const std::string entity = argument(argc, argv, "--entity");
    const std::string transport = argument(argc, argv, "--transport");
    if (transport != "secure" && transport != "crc") {
      throw std::runtime_error("unsupported --transport (want secure|crc)");
    }
    const std::string key = read_key(argument(argc, argv, "--key-file"));

    librados::Rados cluster;
    check(cluster.init2(entity.c_str(), "ceph", 0), "init2");
    check(cluster.conf_set("mon_host", monitors.c_str()), "set monitors");
    check(cluster.conf_set("key", key.c_str()), "set key");
    check(cluster.conf_set("fsid", fsid.c_str()), "set fsid");
    check(cluster.conf_set("ms_client_mode", transport.c_str()), "set ms_client_mode");
    check(cluster.conf_set("ms_service_mode", transport.c_str()), "set ms_service_mode");
    check(cluster.conf_set("ms_cluster_mode", transport.c_str()), "set ms_cluster_mode");
    check(cluster.connect(), "connect");
    librados::IoCtx io;
    check(cluster.ioctx_create(pool.c_str(), io), "open pool");

    rusage before{};
    check(getrusage(RUSAGE_SELF, &before), "getrusage before");
    std::vector<Row> rows;
    rows.reserve(36);
    for (const auto size : sizes) {
      for (const auto concurrency : concurrencies) {
        for (const auto* workload : workloads) {
          rows.push_back(run_row(io, transport, size, concurrency, workload));
        }
      }
    }
    rusage after{};
    check(getrusage(RUSAGE_SELF, &after), "getrusage after");
    const std::uint64_t user_delta = cpu_ns(after.ru_utime) - cpu_ns(before.ru_utime);
    const std::uint64_t system_delta = cpu_ns(after.ru_stime) - cpu_ns(before.ru_stime);
    emit_json(transport, rows, user_delta, system_delta);
    io.close();
    cluster.shutdown();
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "rados-r13-native: " << error.what() << '\n';
    return 1;
  }
}
