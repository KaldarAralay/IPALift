#pragma once

#include <filesystem>
#include <string>

namespace reconstruction_core {

struct FixturePayload {
  std::string body;
  std::string source;
  std::string error;

  [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

class FileFixtureService {
 public:
  explicit FileFixtureService(std::filesystem::path path);
  [[nodiscard]] FixturePayload load() const;

 private:
  std::filesystem::path path_;
};

}  // namespace reconstruction_core
