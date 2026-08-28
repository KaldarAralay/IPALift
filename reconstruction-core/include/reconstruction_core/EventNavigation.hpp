#pragma once

#include <cstddef>
#include <string>
#include <variant>
#include <vector>

namespace reconstruction_core {

struct Route {
  std::string id;
  std::string title;

  friend bool operator==(const Route&, const Route&) = default;
};

struct InitializationStarted {};
struct InitializationSucceeded {};
struct InitializationFailed {
  std::string reason;
};
struct ResourceLoading {
  std::string resource;
  std::string source;
};
struct ResourceLoadSucceeded {
  std::string resource;
  std::size_t itemCount;
  std::string source;
};
struct ResourceLoadFailed {
  std::string resource;
  std::string reason;
};
struct RouteChanged {
  Route previous;
  Route current;
};
struct InputReceived {
  std::string action;
};
struct StateSaved {
  std::string destination;
};

using AppEvent =
    std::variant<InitializationStarted, InitializationSucceeded, InitializationFailed,
                 ResourceLoading, ResourceLoadSucceeded, ResourceLoadFailed, RouteChanged,
                 InputReceived, StateSaved>;

class EventJournal {
 public:
  void publish(AppEvent event);
  [[nodiscard]] const std::vector<AppEvent>& events() const noexcept;

  template <typename Event>
  [[nodiscard]] std::size_t count() const noexcept {
    std::size_t total = 0;
    for (const AppEvent& event : events_) {
      if (std::holds_alternative<Event>(event)) {
        ++total;
      }
    }
    return total;
  }

 private:
  std::vector<AppEvent> events_;
};

class NavigationState {
 public:
  NavigationState(EventJournal& events, Route initial);

  [[nodiscard]] const Route& current() const noexcept;
  [[nodiscard]] std::size_t depth() const noexcept;
  [[nodiscard]] bool replace(Route route);
  [[nodiscard]] bool push(Route route);
  [[nodiscard]] bool pop();

 private:
  EventJournal* events_;
  std::vector<Route> routes_;
};

}  // namespace reconstruction_core
