# Adapter boundary

The core owns mechanisms whose behavior is independent of the recovered application. An adapter owns
all recovered facts and every product decision made while reconstructing a particular IPA.

| Shared core owns | App adapter owns |
|---|---|
| XML syntax and descriptor execution | Element/class/property descriptors and evidence addresses |
| Reading a local fixture path | Fixture files, resource IDs, and their interpretation |
| Typed event containers and route-stack mechanics | Route names, transitions, input mapping, and view state |
| Versioned key/value serialization | Namespace, legacy magic, keys, defaults, and typed domain mapping |
| PNG validation/CgBI conversion and image loading | Selected source assets, hashes, provenance, and layout |
| Diagnostic bitmap glyph rendering | Fonts/assets required for product-faithful UI |
| CMake staging and parameterized build/test orchestration | Target names, executable composition, smoke arguments |
| Traceability format and confidence rules | Evidence IDs, manual IDs, claims, and source locations |

An adapter may wrap a core type to preserve an application API, but it must not fork a core
implementation or add application descriptors to the shared parser.

The package intentionally does not contain recovered application models, controllers, endpoint
knowledge, layouts, or evidence assertions. A gap moves into the core only after more than one app
demonstrates the same mechanism and a synthetic core test can describe it without app vocabulary.
