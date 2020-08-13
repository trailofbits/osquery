/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <dbus/dbus.h>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

int bus_iter_get_basic_and_next2(DBusMessageIter* iter,
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

void genUnits(QueryData& results) {
  DBusConnection* c;
  DBusError error;
  DBusMessage *systemd_message = nullptr, *reply = nullptr;
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

    if (bus_iter_get_basic_and_next2(&sub2, DBUS_TYPE_STRING, &id, true) < 0 ||
        bus_iter_get_basic_and_next2(
            &sub2, DBUS_TYPE_STRING, &description, true) < 0 ||
        bus_iter_get_basic_and_next2(
            &sub2, DBUS_TYPE_STRING, &load_state, true) < 0 ||
        bus_iter_get_basic_and_next2(
            &sub2, DBUS_TYPE_STRING, &active_state, true) < 0 ||
        bus_iter_get_basic_and_next2(
            &sub2, DBUS_TYPE_STRING, &sub_state, true) < 0 ||
        bus_iter_get_basic_and_next2(
            &sub2, DBUS_TYPE_STRING, &following, true) < 0 ||
        bus_iter_get_basic_and_next2(
            &sub2, DBUS_TYPE_OBJECT_PATH, &unit_path, true) < 0 ||
        bus_iter_get_basic_and_next2(&sub2, DBUS_TYPE_UINT32, &job_id, true) <
            0 ||
        bus_iter_get_basic_and_next2(&sub2, DBUS_TYPE_STRING, &job_type, true) <
            0 ||
        bus_iter_get_basic_and_next2(
            &sub2, DBUS_TYPE_OBJECT_PATH, &job_path, false) < 0) {
      VLOG(1) << "Error failed to parse reply";
      goto finish;
    }
    r["name"] = id;
    auto type = osquery::split(id, ".");
    r["type"] = type.back();
    r["load_state"] = load_state;
    r["active_state"] = active_state;
    r["sub_state"] = sub_state;
    results.push_back(r);

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

QueryData genSystemdUnits(QueryContext& context) {
  QueryData results;
  genUnits(results);
  return results;
}

} // namespace tables
} // namespace osquery
