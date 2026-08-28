#include "reconstruction_core/EventNavigation.hpp"

#include <stdexcept>
#include <utility>

namespace reconstruction_core {

void EventJournal::publish(AppEvent event) {
  events_.push_back(std::move(event));
}

const std::vector<AppEvent>& EventJournal::events() const noexcept {
  return events_;
}

NavigationState::NavigationState(EventJournal& events, Route initial) : events_(&events) {
  if (initial.id.empty()) {
    throw std::invalid_argument("an initial route requires a stable id");
  }
  routes_.push_back(std::move(initial));
}

const Route& NavigationState::current() const noexcept {
  return routes_.back();
}

std::size_t NavigationState::depth() const noexcept {
  return routes_.size();
}

bool NavigationState::replace(Route route) {
  if (route.id.empty()) {
    throw std::invalid_argument("a route requires a stable id");
  }
  if (routes_.back() == route) {
    return false;
  }
  const Route previous = routes_.back();
  routes_.back() = std::move(route);
  events_->publish(RouteChanged{previous, routes_.back()});
  return true;
}

bool NavigationState::push(Route route) {
  if (route.id.empty()) {
    throw std::invalid_argument("a route requires a stable id");
  }
  const Route previous = routes_.back();
  routes_.push_back(std::move(route));
  events_->publish(RouteChanged{previous, routes_.back()});
  return true;
}

bool NavigationState::pop() {
  if (routes_.size() <= 1) {
    return false;
  }
  const Route previous = routes_.back();
  routes_.pop_back();
  events_->publish(RouteChanged{previous, routes_.back()});
  return true;
}

}  // namespace reconstruction_core
