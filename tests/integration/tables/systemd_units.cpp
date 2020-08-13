/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for systemd_units
// Spec file: specs/linux/systemd_units.table

#include <dbus/dbus.h>

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class SystemdUnitsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SystemdUnitsTest, test_sanity) {
  auto const data = execute_query("select * from systemd_units");

  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"type", NonEmptyString},
      {"load_state", NormalType},
      {"active_state", NormalType},
      {"sub_state", NormalType},
  };
  validate_rows(data, row_map);
}

TEST_F(SystemdUnitsTest, test_connection) {
  DBusConnection* c = nullptr;
  DBusError error;

  dbus_error_init(&error);
  c = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

  ASSERT_NE(c, nullptr);
}

} // namespace table_tests
} // namespace osquery
