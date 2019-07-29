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

using UserLocalGroupCallback = std::function<Row(const std::string&, LPCWSTR, const std::wstring&, const std::string&)>;

void processDomainUserGroups(const std::wstring& domainName,
			     std::string uid,
                             std::string user,
                             QueryData& results,
                             UserLocalGroupCallback callback
                             );
}
}
