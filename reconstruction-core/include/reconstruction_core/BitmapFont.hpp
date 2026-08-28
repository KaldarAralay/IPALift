#pragma once

#include <SDL3/SDL.h>

#include <string_view>

namespace reconstruction_core {

void drawText(SDL_Renderer* renderer, std::string_view text, float x, float y,
              float scale, SDL_Color color);
[[nodiscard]] float textWidth(std::string_view text, float scale) noexcept;

}  // namespace reconstruction_core
