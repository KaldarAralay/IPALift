#include "reconstruction_core/ImageLoader.hpp"

namespace reconstruction_core {

LoadedTexture loadPngTexture(SDL_Renderer*, const std::filesystem::path&) {
  return {nullptr, 0, 0, "PNG loading is not implemented for this platform"};
}

}  // namespace reconstruction_core
