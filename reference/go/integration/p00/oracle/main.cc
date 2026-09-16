#include <rados/librados.hpp>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::string hex(const std::string& value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (unsigned char byte : value) {
    output << std::setw(2) << static_cast<unsigned>(byte);
  }
  return output.str();
}

std::string json_escape(const std::string& value) {
  std::ostringstream output;
  for (unsigned char byte : value) {
    switch (byte) {
      case '\\': output << "\\\\"; break;
      case '"': output << "\\\""; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (byte < 0x20) {
          output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<unsigned>(byte);
        } else {
          output << byte;
        }
    }
  }
  return output.str();
}

int fail(const std::string& operation, int result) {
  std::cout << "{\"status\":\"failed\",\"operation\":\""
            << json_escape(operation) << "\",\"result\":" << result << "}\n";
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 6 || std::string(argv[1]) != "smoke") {
    std::cerr << "usage: rados-reference smoke CLIENT_ID CONF POOL OBJECT\n";
    return 2;
  }

  const std::string client_id = argv[2];
  const std::string conf = argv[3];
  const std::string pool = argv[4];
  const std::string object = argv[5];
  const std::string payload("go-librados-p00\0binary", 22);

  librados::Rados cluster;
  int result = cluster.init2(client_id.c_str(), "ceph", 0);
  if (result < 0) return fail("init", result);
  result = cluster.conf_read_file(conf.c_str());
  if (result < 0) return fail("conf_read_file", result);
  result = cluster.connect();
  if (result < 0) return fail("connect", result);

  librados::IoCtx io;
  result = cluster.ioctx_create(pool.c_str(), io);
  if (result < 0) return fail("ioctx_create", result);

  ceph::bufferlist input;
  input.append(payload);
  result = io.write_full(object, input);
  if (result < 0) return fail("write_full", result);
  const uint64_t write_version = io.get_last_version();

  ceph::bufferlist output;
  result = io.read(object, output, payload.size() + 1, 0);
  if (result < 0) return fail("read", result);
  const uint64_t read_version = io.get_last_version();
  const std::string actual = output.to_str();
  if (actual != payload) return fail("compare", -1);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  const uint32_t hash_position = io.get_object_pg_hash_position(object);
#pragma GCC diagnostic pop
  result = io.remove(object);
  if (result < 0) return fail("remove", result);

  std::cout << "{\"status\":\"passed\",\"pool\":\"" << json_escape(pool)
            << "\",\"object\":\"" << json_escape(object)
            << "\",\"payload_hex\":\"" << hex(actual)
            << "\",\"write_version\":" << write_version
            << ",\"read_version\":" << read_version
            << ",\"pg_hash_position\":" << hash_position << "}\n";
  io.close();
  cluster.shutdown();
  return 0;
}