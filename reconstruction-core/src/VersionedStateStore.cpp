#include "reconstruction_core/VersionedStateStore.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <utility>

namespace reconstruction_core {
namespace {

std::string encode(const std::string& value) {
  std::ostringstream output;
  output << std::uppercase << std::hex;
  for (const unsigned char character : value) {
    if (character == '%' || character == '\n' || character == '\r' || character == '=') {
      output << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(character);
    } else {
      output << static_cast<char>(character);
    }
  }
  return output.str();
}

bool decode(const std::string& value, std::string& output) {
  output.clear();
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (value[index] != '%') {
      output.push_back(value[index]);
      continue;
    }
    if (index + 2 >= value.size()) {
      return false;
    }
    unsigned int decoded = 0;
    std::istringstream hex(value.substr(index + 1, 2));
    hex >> std::hex >> decoded;
    if (!hex || decoded > 255) {
      return false;
    }
    output.push_back(static_cast<char>(decoded));
    index += 2;
  }
  return true;
}

}  // namespace

VersionedStateStore::VersionedStateStore(std::filesystem::path path, StateFormat format)
    : path_(std::move(path)), format_(std::move(format)) {}

StateLoadResult VersionedStateStore::load() const {
  StateLoadResult result;
  std::error_code existsError;
  if (!std::filesystem::exists(path_, existsError)) {
    if (existsError) {
      result.error = "could not check persistent state: " + existsError.message();
    }
    return result;
  }
  result.found = true;
  std::ifstream input(path_, std::ios::binary);
  if (!input) {
    result.error = "could not open persistent state";
    return result;
  }
  std::string header;
  std::getline(input, header);
  if (header != format_.magic) {
    result.error = "persistent state header is invalid";
    return result;
  }
  std::string line;
  while (std::getline(input, line)) {
    const std::size_t separator = line.find('=');
    if (separator == std::string::npos) {
      result.error = "persistent state contains an invalid line";
      return result;
    }
    std::string decoded;
    if (!decode(line.substr(separator + 1), decoded)) {
      result.error = "persistent state contains invalid escaping";
      return result;
    }
    result.values[line.substr(0, separator)] = std::move(decoded);
  }
  if (result.values["version"] != std::to_string(format_.version)) {
    result.error = "unsupported persistent state version";
  } else if (!format_.namespaceId.empty() &&
             result.values["namespace"] != format_.namespaceId) {
    result.error = "persistent state namespace does not match";
  }
  result.values.erase("version");
  result.values.erase("namespace");
  return result;
}

std::string VersionedStateStore::save(const StateValues& values) const {
  std::error_code directoryError;
  if (!path_.parent_path().empty()) {
    std::filesystem::create_directories(path_.parent_path(), directoryError);
    if (directoryError) {
      return "could not create persistent state directory: " + directoryError.message();
    }
  }
  std::ofstream output(path_, std::ios::binary | std::ios::trunc);
  if (!output) {
    return "could not write persistent state";
  }
  output << format_.magic << '\n';
  if (!format_.namespaceId.empty()) {
    output << "namespace=" << encode(format_.namespaceId) << '\n';
  }
  output << "version=" << format_.version << '\n';
  for (const auto& [key, value] : values) {
    if (key.empty() || key == "namespace" || key == "version" ||
        key.find('=') != std::string::npos) {
      return "persistent state contains a reserved or invalid key";
    }
    output << key << '=' << encode(value) << '\n';
  }
  return output ? std::string{} : "failed while writing persistent state";
}

const std::filesystem::path& VersionedStateStore::path() const noexcept {
  return path_;
}

const StateFormat& VersionedStateStore::format() const noexcept {
  return format_;
}

}  // namespace reconstruction_core
