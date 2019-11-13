/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "complex_example.h"

using namespace osquery;

/**
 * @brief A more 'complex' example table is provided to assist with tests.
 *
 * This table will access options and flags known to the extension.
 * An extension should not assume access to any CLI flags- rather, access is
 * provided via the osquery-meta table: osquery_flags.
 *
 * There is no API/C++ wrapper to provide seamless use of flags yet.
 * We can force an implicit query to the manager though.
 *
 * Database access should be mediated by the *Database functions.
 * Direct use of the "database" registry will lead to undefined behavior.
 */

TableColumns ComplexExampleTable::columns() const {
  return {
    std::make_tuple("flag_test", TEXT_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("database_test", TEXT_TYPE, ColumnOptions::DEFAULT),
  };
}

TableRows ComplexExampleTable::generate(QueryContext& request) {
  auto r = make_table_row();

  // Use the basic 'force' flag to check implicit SQL usage.
  auto flags = SQL::selectFrom(
      {"default_value"}, "osquery_flags", "name", EQUALS, "force");
  if (flags.size() > 0) {
    r["flag_test"] = flags[0]["default_value"];
  }

  std::string content;
  setDatabaseValue(kPersistentSettings, "complex_example", "1");
  if (getDatabaseValue(kPersistentSettings, "complex_example", content)) {
    r["database_test"] = content;
  }

  TableRows result;
  result.push_back(std::move(r));
  return result;
}

