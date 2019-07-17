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

/* #include <windows.h> */

namespace osquery {
namespace tables {

using LocalGroupMemberCallback = std::function<Status( const std::wstring& , const std::string& , LOCALGROUP_MEMBERS_INFO_1& , Row& )>;

Status accountNameToSidString(const std::string& accountName, const std::wstring& domain, std::string& sidString);

Status genMembersOfLocalGroup(
    const std::wstring& domain,
    const std::string& groupname,
    QueryData& results,
    LocalGroupMemberCallback callback
    );

void genFlatMembersOfGroup(
    const std::wstring& domain,
    const std::string& groupname,
    const std::string& original_groupname,
    std::string& path,
    QueryData& results,
    int depth
    );

}
}
