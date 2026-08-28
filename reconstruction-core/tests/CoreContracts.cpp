#include "reconstruction_core/EventNavigation.hpp"
#include "reconstruction_core/FixtureService.hpp"
#include "reconstruction_core/VersionedStateStore.hpp"
#include "reconstruction_core/XmlModelRegistry.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(const bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

}  // namespace

int main(const int argc, char** argv) {
  try {
    require(argc == 3, "expected fixture and temporary state paths");
    const reconstruction_core::FixturePayload fixture =
        reconstruction_core::FileFixtureService(argv[1]).load();
    require(fixture.ok(), fixture.error);

    reconstruction_core::XmlModelRegistry registry;
    registry.registerModel(
        {"entry", "SyntheticEntry", "synthetic",
         {{"name", "name", "setName", "synthetic"},
          {"value", "value", "setValue", "synthetic"}}});
    const reconstruction_core::XmlModelParseResult parsed = registry.parse(fixture.body);
    require(parsed.ok() && parsed.models.size() == 1, "generic XML model parse failed");
    require(parsed.models[0].properties.at("name") == "A & B" &&
                parsed.models[0].properties.at("value") == "C < D" &&
                parsed.models[0].unresolvedChildren.size() == 1,
            "XML entity, CDATA, or unresolved-field behavior changed");
    require(!registry.parse("<catalog/>").ok(), "missing registered models must fail");

    reconstruction_core::EventJournal events;
    reconstruction_core::NavigationState navigation(events, {"start", "Start"});
    events.publish(reconstruction_core::ResourceLoading{"fixture", fixture.source});
    require(navigation.replace({"main", "Main"}), "route replacement failed");
    require(navigation.push({"detail", "Detail"}), "route push failed");
    require(navigation.pop(), "route pop failed");
    require(!navigation.pop(), "root route must not pop");
    require(events.count<reconstruction_core::RouteChanged>() == 3 &&
                events.count<reconstruction_core::ResourceLoading>() == 1,
            "typed event journal changed");

    const std::filesystem::path statePath = argv[2];
    std::error_code cleanupError;
    std::filesystem::remove(statePath, cleanupError);
    reconstruction_core::VersionedStateStore state(
        statePath, {"RECONSTRUCTION_STATE", "synthetic-adapter", 3});
    require(state.save({{"name", "A=B%\nC"}, {"score", "42"}}).empty(),
            "versioned state save failed");
    const reconstruction_core::StateLoadResult loaded = state.load();
    require(loaded.ok() && loaded.found && loaded.values.at("name") == "A=B%\nC" &&
                loaded.values.at("score") == "42",
            "versioned state round trip failed");
    require(!reconstruction_core::VersionedStateStore(
                 statePath, {"RECONSTRUCTION_STATE", "different-adapter", 3})
                 .load()
                 .ok(),
            "state namespace guard failed");

    const std::filesystem::path legacyPath = statePath.string() + ".legacy";
    reconstruction_core::VersionedStateStore legacy(legacyPath, {"SYNTHETIC_LEGACY", "", 7});
    require(legacy.save({{"value", "kept"}}).empty(), "custom state format save failed");
    std::ifstream legacyFile(legacyPath, std::ios::binary);
    std::string header;
    std::getline(legacyFile, header);
    require(header == "SYNTHETIC_LEGACY", "custom state magic was not preserved");

    std::cout << "RECONSTRUCTION_CORE_CONTRACTS_OK xml=1 route_events=3 state=v3+custom\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "RECONSTRUCTION_CORE_CONTRACTS_FAILED " << error.what() << '\n';
    return 1;
  }
}
