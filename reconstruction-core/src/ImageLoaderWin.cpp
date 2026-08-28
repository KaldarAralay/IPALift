#include "reconstruction_core/ImageLoader.hpp"

#include <windows.h>
#include <wincodec.h>

#include <cstdint>
#include <string>
#include <vector>

namespace reconstruction_core {
namespace {

template <typename T>
void releaseCom(T*& value) {
  if (value != nullptr) {
    value->Release();
    value = nullptr;
  }
}

std::string hresultMessage(const char* operation, const HRESULT value) {
  return std::string(operation) + " failed (HRESULT " + std::to_string(value) + ")";
}

}  // namespace

LoadedTexture loadPngTexture(SDL_Renderer* renderer, const std::filesystem::path& path) {
  LoadedTexture result;
  const HRESULT apartment = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const bool uninitialize = SUCCEEDED(apartment);
  if (FAILED(apartment) && apartment != RPC_E_CHANGED_MODE) {
    result.error = hresultMessage("CoInitializeEx", apartment);
    return result;
  }

  IWICImagingFactory* factory = nullptr;
  IWICBitmapDecoder* decoder = nullptr;
  IWICBitmapFrameDecode* frame = nullptr;
  IWICFormatConverter* converter = nullptr;

  HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&factory));
  if (SUCCEEDED(hr)) {
    hr = factory->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                                            WICDecodeMetadataCacheOnLoad, &decoder);
  }
  if (SUCCEEDED(hr)) {
    hr = decoder->GetFrame(0, &frame);
  }
  if (SUCCEEDED(hr)) {
    hr = factory->CreateFormatConverter(&converter);
  }
  if (SUCCEEDED(hr)) {
    hr = converter->Initialize(frame, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone,
                               nullptr, 0.0, WICBitmapPaletteTypeCustom);
  }

  UINT width = 0;
  UINT height = 0;
  if (SUCCEEDED(hr)) {
    hr = converter->GetSize(&width, &height);
  }

  std::vector<std::uint8_t> pixels;
  const UINT stride = width * 4U;
  if (SUCCEEDED(hr)) {
    pixels.resize(static_cast<std::size_t>(stride) * height);
    hr = converter->CopyPixels(nullptr, stride, static_cast<UINT>(pixels.size()), pixels.data());
  }

  if (SUCCEEDED(hr)) {
    result.texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_RGBA32,
                                       SDL_TEXTUREACCESS_STATIC, static_cast<int>(width),
                                       static_cast<int>(height));
    if (result.texture == nullptr) {
      result.error = SDL_GetError();
    } else if (!SDL_UpdateTexture(result.texture, nullptr, pixels.data(), static_cast<int>(stride))) {
      result.error = SDL_GetError();
      SDL_DestroyTexture(result.texture);
      result.texture = nullptr;
    } else {
      SDL_SetTextureScaleMode(result.texture, SDL_SCALEMODE_LINEAR);
      result.width = static_cast<int>(width);
      result.height = static_cast<int>(height);
    }
  } else {
    result.error = hresultMessage("Windows PNG decode", hr);
  }

  releaseCom(converter);
  releaseCom(frame);
  releaseCom(decoder);
  releaseCom(factory);
  if (uninitialize) {
    CoUninitialize();
  }
  return result;
}

}  // namespace reconstruction_core
