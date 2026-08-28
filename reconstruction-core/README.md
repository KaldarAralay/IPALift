# Reconstruction Core

reconstruction_core is an optional, app-neutral C++20 library for projects that
reconstruct an application from IPALift evidence. It is not an IPA analyzer and
contains no recovered application models, assets, routes, or behavior.

## Included mechanisms

- **XmlModelRegistry:** descriptor-driven XML parsing with unresolved-field
  reporting.
- **FileFixtureService:** deterministic local fixture loading.
- **EventJournal and NavigationState:** typed event and route-stack mechanics.
- **VersionedStateStore:** application-supplied format identity and versioned
  key/value persistence.
- **ImageLoader:** SDL texture loading through Windows Imaging Component, with
  an explicit non-Windows stub.
- **BitmapFont:** small diagnostic text rendering.
- **tools/normalize_png.py:** standard PNG pass-through and Apple CgBI
  conversion.
- **cmake/ReconstructionHelpers.cmake:** warnings, asset normalization, and
  staging helpers.
- **tools/new_adapter.py:** a minimal out-of-tree application adapter generator.

See [adapter-boundary.md](docs/adapter-boundary.md) and
[traceability-conventions.md](docs/traceability-conventions.md) before adding a
shared mechanism.

## Requirements

The reference workflow uses:

- Windows with Visual Studio 2022
- CMake 3.24 or newer
- Python 3
- Git and network access for the pinned SDL dependency, or a verified local SDL
  source cache

SDL 3.2.22 is pinned to commit
a96677bdf6b4acb84af4ec294e5f60a4e8cbbe03. A local source checkout can be
placed at .deps/sdl3-src or passed as RECONSTRUCTION_CORE_SDL3_SOURCE.

## Build and test

Run:

~~~powershell
cd reconstruction-core
.\scripts\build-and-test.ps1
~~~

The script configures the windows-x64 preset, builds Release, and runs CTest. A
custom CMake generator may be used on other platforms; image loading uses the
documented stub outside Windows.

## Create an application adapter

From the repository root:

~~~powershell
py -3 .\reconstruction-core\tools\new_adapter.py --name ExampleApp --namespace example_app --output ..\example-app-reconstruction
~~~

The generated project contains ten small files: CMake configuration, an
adapter, a deterministic fixture, a contract test, traceability starter, and a
build helper. It references reconstruction_core; it does not copy the
framework. Its build helper accepts the core location explicitly:

~~~powershell
cd ..\example-app-reconstruction
.\scripts\build-and-test.ps1 -CoreRoot ..\IPADecompTool\reconstruction-core
~~~

Keep the generated adapter in a separate repository. Application-specific
descriptors, assets, evidence IDs, persistence formats, routes, input mapping,
and presentation all belong there.
