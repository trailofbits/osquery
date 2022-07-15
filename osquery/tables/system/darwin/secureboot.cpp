/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <memory>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach_error.h>

namespace osquery::tables {

namespace {

enum class SecureBootMode {
  FullSecurity,
  MediumSecurity,
  NoSecurity,
};

struct IoRegistryEntryDeleter final {
  using pointer = io_registry_entry_t;

  void operator()(pointer p) {
    if (p == 0) {
      return;
    }

    IOObjectRelease(p);
  }
};

template <typename Type>
struct TypeDeleter final {
  using pointer = Type;

  void operator()(pointer p) {
    CFRelease(p);
  }
};

using UniqueIoRegistryEntry =
    std::unique_ptr<io_registry_entry_t, IoRegistryEntryDeleter>;

using UniqueCFStringRef =
    std::unique_ptr<CFStringRef, TypeDeleter<CFStringRef>>;

using UniqueCFTypeRef = std::unique_ptr<CFTypeRef, TypeDeleter<CFTypeRef>>;

const std::string kOptionsRegistryEntryPath{"IODeviceTree:/options"};

const std::string kVariableName{
    "94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy"};

bool openRegistryEntry(UniqueIoRegistryEntry& entry, const std::string& path) {
  static mach_port_t master_port{};
  if (master_port == 0 &&
      IOMasterPort(bootstrap_port, &master_port) != KERN_SUCCESS) {
    return false;
  }

  auto entry_ref = IORegistryEntryFromPath(master_port, path.c_str());
  if (entry_ref == 0) {
    return false;
  }

  entry.reset(entry_ref);
  return true;
}

bool getSecureBootSetting(SecureBootMode& mode) {
  mode = SecureBootMode::NoSecurity;

  UniqueIoRegistryEntry options_entry;
  if (!openRegistryEntry(options_entry, kOptionsRegistryEntryPath.c_str())) {
    return false;
  }

  UniqueCFStringRef name;

  {
    auto name_ref = CFStringCreateWithCString(
        kCFAllocatorDefault, kVariableName.c_str(), kCFStringEncodingUTF8);

    if (name_ref == 0) {
      return false;
    }

    name.reset(name_ref);
  }

  UniqueCFTypeRef value;

  {
    auto value_ref =
        IORegistryEntryCreateCFProperty(options_entry.get(), name.get(), 0, 0);

    if (value_ref == 0) {
      return false;
    }

    if (CFGetTypeID(value_ref) != CFDataGetTypeID()) {
      return false;
    }

    value.reset(value_ref);
  }

  auto data_length = CFDataGetLength(static_cast<CFDataRef>(value.get()));
  if (data_length != 1) {
    return false;
  }

  auto data_ptr = CFDataGetBytePtr(static_cast<CFDataRef>(value.get()));

  switch (*data_ptr) {
  case 2:
    mode = SecureBootMode::FullSecurity;
    break;

  case 1:
    mode = SecureBootMode::MediumSecurity;
    break;

  case 0:
    mode = SecureBootMode::NoSecurity;
    break;

  default:
    return false;
  }

  return true;
}

} // namespace

QueryData genSecureBoot(QueryContext& context) {
  SecureBootMode mode{SecureBootMode::NoSecurity};
  if (!getSecureBootSetting(mode)) {
    LOG(ERROR) << "secureboot: Failed to access the following nvram variable: "
               << kVariableName;
    return {};
  }

  int column_value{};
  switch (mode) {
  case SecureBootMode::FullSecurity:
    column_value = 1;
    break;

  case SecureBootMode::MediumSecurity:
    column_value = 2;
    break;

  case SecureBootMode::NoSecurity:
    column_value = 0;
    break;

  default:
    LOG(ERROR) << "secureboot: Invalid SecureBootMode value";
    return {};
  }

  Row row;
  row["secure_boot"] = BIGINT(column_value);

  return {row};
}

} // namespace osquery::tables
