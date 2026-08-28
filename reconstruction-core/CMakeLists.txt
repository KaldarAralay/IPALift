cmake_minimum_required(VERSION 3.24)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(reconstruction_core VERSION 1.0.0 LANGUAGES C CXX)
  include(CTest)
endif()

include(FetchContent)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RECONSTRUCTION_CORE_SDL3_COMMIT
    "a96677bdf6b4acb84af4ec294e5f60a4e8cbbe03"
    CACHE STRING "Pinned SDL3 source commit")
set(RECONSTRUCTION_CORE_SDL3_SOURCE "" CACHE PATH "Optional app-neutral SDL3 source cache")
option(RECONSTRUCTION_CORE_FETCH_SDL3 "Fetch pinned SDL3 when no local cache is available" ON)
option(RECONSTRUCTION_CORE_BUILD_TESTS "Build the neutral core contract tests" ON)

if(NOT TARGET SDL3::SDL3)
  if(NOT RECONSTRUCTION_CORE_SDL3_SOURCE AND
     EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.deps/sdl3-src/CMakeLists.txt")
    set(RECONSTRUCTION_CORE_SDL3_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/.deps/sdl3-src")
  endif()
  set(SDL_SHARED OFF CACHE BOOL "" FORCE)
  set(SDL_STATIC ON CACHE BOOL "" FORCE)
  set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
  set(SDL_TESTS OFF CACHE BOOL "" FORCE)
  if(RECONSTRUCTION_CORE_SDL3_SOURCE)
    FetchContent_Declare(SDL3 SOURCE_DIR "${RECONSTRUCTION_CORE_SDL3_SOURCE}")
  elseif(RECONSTRUCTION_CORE_FETCH_SDL3)
    FetchContent_Declare(
      SDL3
      GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
      GIT_TAG ${RECONSTRUCTION_CORE_SDL3_COMMIT}
      GIT_SHALLOW FALSE
    )
  else()
    message(FATAL_ERROR
      "Provide RECONSTRUCTION_CORE_SDL3_SOURCE or enable RECONSTRUCTION_CORE_FETCH_SDL3")
  endif()
  FetchContent_MakeAvailable(SDL3)
endif()

add_library(reconstruction_core STATIC
  src/BitmapFont.cpp
  src/EventNavigation.cpp
  src/FixtureService.cpp
  src/VersionedStateStore.cpp
  src/XmlModelRegistry.cpp
)
add_library(reconstruction_core::reconstruction_core ALIAS reconstruction_core)
target_include_directories(reconstruction_core PUBLIC include)
target_link_libraries(reconstruction_core PUBLIC SDL3::SDL3)

if(WIN32)
  target_sources(reconstruction_core PRIVATE src/ImageLoaderWin.cpp)
  target_compile_definitions(reconstruction_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
  target_link_libraries(reconstruction_core PUBLIC ole32 windowscodecs)
else()
  target_sources(reconstruction_core PRIVATE src/ImageLoaderStub.cpp)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ReconstructionHelpers.cmake")
reconstruction_enable_warnings(reconstruction_core)

if(BUILD_TESTING AND RECONSTRUCTION_CORE_BUILD_TESTS)
  add_executable(ReconstructionCoreContracts tests/CoreContracts.cpp)
  target_link_libraries(ReconstructionCoreContracts PRIVATE reconstruction_core)
  reconstruction_enable_warnings(ReconstructionCoreContracts)
  add_test(
    NAME reconstruction_core_contracts
    COMMAND ReconstructionCoreContracts
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/catalog.xml"
            "${CMAKE_CURRENT_BINARY_DIR}/test-state/core.state"
  )
  add_test(
    NAME reconstruction_core_png_normalizer
    COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_normalize_png.py"
            --tool "${CMAKE_CURRENT_SOURCE_DIR}/tools/normalize_png.py"
            --work-root "${CMAKE_CURRENT_BINARY_DIR}/png-normalizer-test"
  )
  add_test(
    NAME reconstruction_core_adapter_scaffold
    COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_scaffold.py"
            --generator "${CMAKE_CURRENT_SOURCE_DIR}/tools/new_adapter.py"
            --template "${CMAKE_CURRENT_SOURCE_DIR}/templates/app-adapter"
            --work-root "${CMAKE_CURRENT_BINARY_DIR}/adapter-scaffold-test"
  )
  set_tests_properties(reconstruction_core_contracts reconstruction_core_png_normalizer
                       reconstruction_core_adapter_scaffold PROPERTIES TIMEOUT 30)
endif()
