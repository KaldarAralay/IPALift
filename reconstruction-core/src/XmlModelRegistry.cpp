#include "reconstruction_core/XmlModelRegistry.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <utility>

namespace reconstruction_core {
namespace {

struct XmlNode {
  std::string name;
  std::string text;
  std::vector<XmlNode> children;
};

void replaceAll(std::string& value, const std::string_view from, const std::string_view to) {
  std::size_t position = 0;
  while ((position = value.find(from, position)) != std::string::npos) {
    value.replace(position, from.size(), to);
    position += to.size();
  }
}

std::string trimAndDecode(std::string value) {
  const auto notSpace = [](const unsigned char character) { return std::isspace(character) == 0; };
  const auto begin = std::find_if(value.begin(), value.end(), notSpace);
  const auto end = std::find_if(value.rbegin(), value.rend(), notSpace).base();
  value = begin < end ? std::string(begin, end) : std::string{};
  replaceAll(value, "&lt;", "<");
  replaceAll(value, "&gt;", ">");
  replaceAll(value, "&quot;", "\"");
  replaceAll(value, "&apos;", "'");
  replaceAll(value, "&amp;", "&");
  return value;
}

class XmlReader {
 public:
  explicit XmlReader(const std::string_view input) : input_(input) {}

  XmlNode readDocument() {
    skipMisc();
    if (cursor_ >= input_.size()) {
      fail("the XML document is empty");
    }
    XmlNode root = readElement();
    skipMisc();
    if (cursor_ != input_.size()) {
      fail("unexpected data after the root element");
    }
    return root;
  }

 private:
  [[noreturn]] void fail(const std::string& message) const {
    throw std::runtime_error(message + " at byte " + std::to_string(cursor_));
  }

  [[nodiscard]] bool startsWith(const std::string_view token) const noexcept {
    return input_.substr(cursor_, token.size()) == token;
  }

  void skipWhitespace() {
    while (cursor_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[cursor_])) != 0) {
      ++cursor_;
    }
  }

  void skipUntil(const std::string_view terminator, const std::string& description) {
    const std::size_t end = input_.find(terminator, cursor_);
    if (end == std::string_view::npos) {
      fail("unterminated " + description);
    }
    cursor_ = end + terminator.size();
  }

  void skipMisc() {
    while (true) {
      skipWhitespace();
      if (startsWith("<?")) {
        skipUntil("?>", "processing instruction");
      } else if (startsWith("<!--")) {
        skipUntil("-->", "comment");
      } else {
        return;
      }
    }
  }

  std::string readName() {
    const std::size_t begin = cursor_;
    while (cursor_ < input_.size()) {
      const unsigned char character = static_cast<unsigned char>(input_[cursor_]);
      if (std::isalnum(character) == 0 && character != '_' && character != '-' &&
          character != ':' && character != '.') {
        break;
      }
      ++cursor_;
    }
    if (begin == cursor_) {
      fail("expected an element name");
    }
    return std::string(input_.substr(begin, cursor_ - begin));
  }

  void skipStartTagRemainder(bool& selfClosing) {
    char quote = 0;
    while (cursor_ < input_.size()) {
      const char character = input_[cursor_++];
      if (quote != 0) {
        if (character == quote) {
          quote = 0;
        }
        continue;
      }
      if (character == '\'' || character == '"') {
        quote = character;
      } else if (character == '>') {
        return;
      } else if (character == '/' && cursor_ < input_.size() && input_[cursor_] == '>') {
        ++cursor_;
        selfClosing = true;
        return;
      }
    }
    fail("unterminated start tag");
  }

  XmlNode readElement() {
    if (cursor_ >= input_.size() || input_[cursor_] != '<' || startsWith("</")) {
      fail("expected a start tag");
    }
    ++cursor_;
    XmlNode node;
    node.name = readName();
    bool selfClosing = false;
    skipStartTagRemainder(selfClosing);
    if (selfClosing) {
      return node;
    }

    while (cursor_ < input_.size()) {
      if (startsWith("</")) {
        cursor_ += 2;
        const std::string closeName = readName();
        skipWhitespace();
        if (cursor_ >= input_.size() || input_[cursor_] != '>') {
          fail("unterminated end tag");
        }
        ++cursor_;
        if (closeName != node.name) {
          fail("mismatched end tag </" + closeName + "> for <" + node.name + ">");
        }
        node.text = trimAndDecode(std::move(node.text));
        return node;
      }
      if (startsWith("<![CDATA[")) {
        cursor_ += 9;
        const std::size_t end = input_.find("]]>", cursor_);
        if (end == std::string_view::npos) {
          fail("unterminated CDATA section");
        }
        node.text.append(input_.substr(cursor_, end - cursor_));
        cursor_ = end + 3;
      } else if (startsWith("<!--")) {
        skipUntil("-->", "comment");
      } else if (input_[cursor_] == '<') {
        node.children.push_back(readElement());
      } else {
        const std::size_t end = input_.find('<', cursor_);
        if (end == std::string_view::npos) {
          fail("unterminated <" + node.name + "> element");
        }
        node.text.append(input_.substr(cursor_, end - cursor_));
        cursor_ = end;
      }
    }
    fail("unterminated <" + node.name + "> element");
  }

  std::string_view input_;
  std::size_t cursor_{};
};

void collectModels(const XmlNode& node, const XmlModelRegistry& registry,
                   XmlModelParseResult& result) {
  if (const XmlModelDescriptor* descriptor = registry.descriptor(node.name);
      descriptor != nullptr) {
    ParsedXmlModel model;
    model.element = descriptor->element;
    model.runtimeClass = descriptor->runtimeClass;
    model.evidence = descriptor->evidence;
    for (const XmlNode& child : node.children) {
      const auto binding = std::find_if(
          descriptor->fields.begin(), descriptor->fields.end(),
          [&child](const XmlFieldBinding& field) { return field.childElement == child.name; });
      if (binding == descriptor->fields.end()) {
        model.unresolvedChildren.push_back(child.name);
      } else {
        model.properties[binding->property] = child.text;
      }
    }
    result.models.push_back(std::move(model));
    return;
  }
  for (const XmlNode& child : node.children) {
    collectModels(child, registry, result);
  }
}

}  // namespace

void XmlModelRegistry::registerModel(XmlModelDescriptor descriptor) {
  if (descriptor.element.empty() || descriptor.runtimeClass.empty()) {
    throw std::invalid_argument("XML model descriptors require element and runtime class names");
  }
  if (this->descriptor(descriptor.element) != nullptr) {
    throw std::invalid_argument("duplicate XML model element: " + descriptor.element);
  }
  descriptors_.push_back(std::move(descriptor));
}

const XmlModelDescriptor* XmlModelRegistry::descriptor(const std::string_view element) const noexcept {
  const auto found = std::find_if(descriptors_.begin(), descriptors_.end(),
                                  [element](const XmlModelDescriptor& value) {
                                    return value.element == element;
                                  });
  return found == descriptors_.end() ? nullptr : &*found;
}

const std::vector<XmlModelDescriptor>& XmlModelRegistry::descriptors() const noexcept {
  return descriptors_;
}

XmlModelParseResult XmlModelRegistry::parse(const std::string_view xml) const {
  XmlModelParseResult result;
  try {
    const XmlNode root = XmlReader(xml).readDocument();
    collectModels(root, *this, result);
    if (result.models.empty()) {
      result.error = "no registered XML model elements were found";
    }
  } catch (const std::exception& error) {
    result.error = error.what();
    result.models.clear();
  }
  return result;
}

}  // namespace reconstruction_core
