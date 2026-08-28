#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace reconstruction_core {

struct XmlFieldBinding {
  std::string childElement;
  std::string property;
  std::string setter;
  std::string evidence;
};

struct XmlModelDescriptor {
  std::string element;
  std::string runtimeClass;
  std::string evidence;
  std::vector<XmlFieldBinding> fields;
};

struct ParsedXmlModel {
  std::string element;
  std::string runtimeClass;
  std::map<std::string, std::string> properties;
  std::vector<std::string> unresolvedChildren;
  std::string evidence;
};

struct XmlModelParseResult {
  std::vector<ParsedXmlModel> models;
  std::vector<std::string> unresolvedModelElements;
  std::string error;

  [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

class XmlModelRegistry {
 public:
  void registerModel(XmlModelDescriptor descriptor);
  [[nodiscard]] const XmlModelDescriptor* descriptor(std::string_view element) const noexcept;
  [[nodiscard]] const std::vector<XmlModelDescriptor>& descriptors() const noexcept;
  [[nodiscard]] XmlModelParseResult parse(std::string_view xml) const;

 private:
  std::vector<XmlModelDescriptor> descriptors_;
};

}  // namespace reconstruction_core
