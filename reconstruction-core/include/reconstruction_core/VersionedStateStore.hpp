#pragma once

#include <filesystem>
#include <map>
#include <string>

namespace reconstruction_core {

using StateValues = std::map<std::string, std::string>;

struct StateFormat {
  std::string magic{"RECONSTRUCTION_STATE"};
  std::string namespaceId;
  int version{1};
};

struct StateLoadResult {
  bool found{};
  StateValues values;
  std::string error;

  [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

class VersionedStateStore {
 public:
  VersionedStateStore(std::filesystem::path path, StateFormat format);
  [[nodiscard]] StateLoadResult load() const;
  [[nodiscard]] std::string save(const StateValues& values) const;
  [[nodiscard]] const std::filesystem::path& path() const noexcept;
  [[nodiscard]] const StateFormat& format() const noexcept;

 private:
  std::filesystem::path path_;
  StateFormat format_;
};

}  // namespace reconstruction_core
