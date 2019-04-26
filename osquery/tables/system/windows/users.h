/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */
// clang-format off
#include <LM.h>
// clang-format on

namespace osquery {
namespace tables {
void processDomainAccounts(const std::wstring &domainNameW,
                           std::set<std::string>& processedSids,
                           QueryData& results);
}
}
