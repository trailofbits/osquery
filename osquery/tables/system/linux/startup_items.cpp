/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <dbus/dbus.h>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kSystemItemPaths = {"/etc/xdg/autostart/"};

const std::vector<std::string> kSystemScriptPaths = {"/etc/init.d/"};

void genAutoStartItems(const std::string& sysdir, QueryData& results) {
  std::vector<std::string> dirFiles;
  auto s = osquery::listFilesInDirectory(sysdir, dirFiles, false);
  if (!s.ok()) {
    VLOG(1) << "Error traversing " << sysdir << ": " << s.what();
  }
  for (const auto& file : dirFiles) {
    Row r;
    std::string content;
    if (readFile(file, content)) {
      for (const auto& line : osquery::split(content, "\n")) {
        if (line.find("Name=") == 0) {
          auto details = osquery::split(line, "=");
          if (details.size() == 2) {
            r["name"] = details[1];
          }
        }
        if (line.find("Exec=") == 0) {
          auto details = osquery::split(line, "=");
          if (details.size() == 2) {
            r["path"] = details[1];
          }
        }
      }
    }
    r["type"] = "Startup Item";
    r["status"] = "enabled";
    r["source"] = sysdir;

    auto username = osquery::split(sysdir, "/");
    if (username.size() > 1 && username[0] == "home") {
      r["username"] = username[1];
    }
    results.push_back(r);
  }
}

void genAutoStartScripts(const std::string& sysdir, QueryData& results) {
  std::vector<std::string> dirFiles;
  auto s = osquery::listFilesInDirectory(sysdir, dirFiles, false);
  if (!s.ok()) {
    VLOG(1) << "Error traversing " << sysdir << ": " << s.what();
  }
  for (const auto& file : dirFiles) {
    Row r;
    r["name"] = osquery::split(file, "/").back();
    r["path"] = file;
    r["type"] = "Startup Item";
    r["status"] = "enabled";
    r["source"] = sysdir;
    auto username = osquery::split(sysdir, "/");
    if (username.size() > 1 && username[0] == "home") {
      r["username"] = username[1];
    }
    results.push_back(r);
  }
}

int bus_iter_get_basic_and_next(DBusMessageIter* iter,
                                int type,
                                void* data,
                                bool next) {
  if (dbus_message_iter_get_arg_type(iter) != type) {
    return -1;
  }

  dbus_message_iter_get_basic(iter, data);

  if (dbus_message_iter_next(iter) != next) {
    return -1;
  }

  return 0;
}

void genSystemDItems(QueryData& results) {
  DBusConnection* c;
  DBusError error;
  DBusMessage *systemd_message = nullptr, *reply = nullptr;
  dbus_error_init(&error);
  DBusMessageIter iter, sub, sub2;

  dbus_error_init(&error);
  c = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

  if (c == NULL || dbus_error_is_set(&error)) {
    VLOG(1) << "Error dbus failed: " << error.name << error.message;
    goto finish;
  }

  systemd_message =
      dbus_message_new_method_call("org.freedesktop.systemd1",
                                   "/org/freedesktop/systemd1",
                                   "org.freedesktop.systemd1.Manager",
                                   "ListUnits");
  if (!systemd_message) {
    VLOG(1) << "Error failed to create dbus message";
    goto finish;
  }
  reply =
      dbus_connection_send_with_reply_and_block(c, systemd_message, -1, &error);
  if (dbus_error_is_set(&error)) {
    VLOG(1) << "Error dbus failed: " << error.name << error.message;
    goto finish;
  }

  if (!dbus_message_iter_init(reply, &iter) ||
      dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
      dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
    VLOG(1) << "Error failed to parse reply";
    goto finish;
  }
  dbus_message_iter_recurse(&iter, &sub);

  while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
    Row r;
    const char *id, *description, *load_state, *active_state, *sub_state,
        *following, *unit_path, *job_type, *job_path;
    std::uint32_t job_id = 0U;
    if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
      VLOG(1) << "Error failed to parse reply";
      goto finish;
    }
    dbus_message_iter_recurse(&sub, &sub2);

    if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) < 0 ||
        bus_iter_get_basic_and_next(
            &sub2, DBUS_TYPE_STRING, &description, true) < 0 ||
        bus_iter_get_basic_and_next(
            &sub2, DBUS_TYPE_STRING, &load_state, true) < 0 ||
        bus_iter_get_basic_and_next(
            &sub2, DBUS_TYPE_STRING, &active_state, true) < 0 ||
        bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &sub_state, true) <
            0 ||
        bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &following, true) <
            0 ||
        bus_iter_get_basic_and_next(
            &sub2, DBUS_TYPE_OBJECT_PATH, &unit_path, true) < 0 ||
        bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &job_id, true) <
            0 ||
        bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &job_type, true) <
            0 ||
        bus_iter_get_basic_and_next(
            &sub2, DBUS_TYPE_OBJECT_PATH, &job_path, false) < 0) {
      VLOG(1) << "Error failed to parse reply";
      goto finish;
    }
    if (strcmp(active_state, "active") == 0) {
      r["name"] = id;
      r["path"] = unit_path;
      r["type"] = "Startup Item";
      r["status"] = "enabled";
      results.push_back(r);
    }

    dbus_message_iter_next(&sub);
  }
finish:
  if (systemd_message) {
    dbus_message_unref(systemd_message);
  }
  if (reply) {
    dbus_message_unref(reply);
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // User specific
  for (const auto& dir : getHomeDirectories()) {
    auto itemsDir = dir / "/.config/autostart/";
    auto scriptsDir = dir / "/.config/autostart-scripts/";
    genAutoStartItems(itemsDir.string(), results);
    genAutoStartScripts(scriptsDir.string(), results);
  }

  // System specific
  for (const auto& dir : kSystemScriptPaths) {
    genAutoStartScripts(dir, results);
  }
  for (const auto& dir : kSystemItemPaths) {
    genAutoStartItems(dir, results);
  }

  genSystemDItems(results);
  return results;
}

} // namespace tables
} // namespace osquery
