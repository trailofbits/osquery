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

Status getGroupRow(const std::wstring& domainNameW,
                   LPCWSTR groupName,
                   LPCWSTR comment,
                   const std::string& scope,
                   Row& r);
void processGroups(const std::wstring &domainName,
                         QueryData& results, bool scope_column=false);
}
}
