/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */
#pragma once

#include <osquery/core.h>
#include <osquery/tables.h>
// clang-format off
#include <LM.h>
// clang-format on

namespace osquery {
namespace tables {
void processDomainAccounts(const std::wstring &domainNameW,
                           std::set<std::string>& processedSids,
                           QueryData& results);

std::string getUserHomeDir(const std::string& sid);

}
}
