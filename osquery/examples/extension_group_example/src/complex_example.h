/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

namespace osquery {
class ComplexExampleTable : public TablePlugin {
 private:
  TableColumns columns() const;
  TableRows generate(QueryContext& request);
};
} // namespace osquery
