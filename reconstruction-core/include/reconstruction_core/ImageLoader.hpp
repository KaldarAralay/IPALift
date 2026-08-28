#pragma once

#include <SDL3/SDL.h>

#include <filesystem>
#include <string>

namespace reconstruction_core {

struct LoadedTexture {
  SDL_Texture* texture{};
  int width{};
  int height{};
  std::string error;
};

[[nodiscard]] LoadedTexture loadPngTexture(SDL_Renderer* renderer,
                                           const std::filesystem::path& path);

}  // namespace reconstruction_core
