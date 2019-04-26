/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <string>

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

Row getUserGroupRow(const std::string& uid, LPCWSTR groupname, const std::wstring& domainName, const std::string& username);

/* void processDomainUserGroups(const std::string& domainName, */
void processDomainUserGroups(const std::wstring& domainName,
			     std::string uid,
                             std::string user,
                             QueryData& results);
}
}
