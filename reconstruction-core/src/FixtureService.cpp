#include "reconstruction_core/FixtureService.hpp"

#include <fstream>
#include <iterator>
#include <utility>

namespace reconstruction_core {

FileFixtureService::FileFixtureService(std::filesystem::path path) : path_(std::move(path)) {}

FixturePayload FileFixtureService::load() const {
  std::ifstream stream(path_, std::ios::binary);
  if (!stream) {
    return {{}, path_.string(), "could not open the local fixture"};
  }
  std::string body{std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
  if (body.empty()) {
    return {{}, path_.string(), "the local fixture is empty"};
  }
  return {std::move(body), path_.string(), {}};
}

}  // namespace reconstruction_core
