/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "example.h"

namespace osquery {
TableColumns ExampleTable::columns() const {
  return {
    std::make_tuple("example_text", TEXT_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("example_integer", INTEGER_TYPE, ColumnOptions::DEFAULT),
  };
}

TableRows ExampleTable::generate(QueryContext& request) {
  TableRows results;

  auto r = make_table_row();
  r["example_text"] = "example";
  r["example_integer"] = INTEGER(1);

  results.push_back(std::move(r));
  return results;
}
} // namespace osquery
