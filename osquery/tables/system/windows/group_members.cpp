/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/system.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/tables/system/windows/registry.h"
#include "osquery/tables/system/windows/user_groups.h"
#include "osquery/tables/system/windows/domain_user_groups.h" // get member local
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/process/process.h>
#include <osquery/process/windows/process_ops.h>

namespace osquery {

std::string psidToString(PSID sid);
int getGidFromSid(PSID sid);

namespace tables {

Status genGroupMemberRow(
    const std::wstring& domain,
    const std::string& groupname,
    LOCALGROUP_MEMBERS_INFO_1& member,
    Row& r
    ) {

  r["member_sid"] = psidToString(member.lgrmi1_sid);
  r["membername"] = wstringToString(member.lgrmi1_name);
  r["groupname"] = groupname;
  r["domain"] = wstringToString(domain.c_str());

  switch(member.lgrmi1_sidusage) {
    case SidTypeUser:
        r["member_type"] = "User";
        break;
    case SidTypeGroup:
        r["member_type"] = "Group";
        break;
    case SidTypeWellKnownGroup:
        r["member_type"] = "Well Known Group";
        break;
    case SidTypeDeletedAccount:
        r["member_type"] = "Deleted Account";
        break;
    case SidTypeUnknown:
        r["member_type"] = "Unknown";
        break;
    default:
        r["member_type"] = "N/A";
        break;
  }



  auto sidSmartPtr = getSidFromUsername(stringToWstring(groupname).c_str(), domain.c_str());
  if (sidSmartPtr == nullptr) {
    return Status::failure("Failed to find a SID for group: " + groupname);
  } else {
    auto sidPtr = static_cast<PSID>(sidSmartPtr.get());
    r["group_sid"] = psidToString(sidPtr);
  }

  return Status::success();
}


QueryData genGroupMembers(QueryContext& context) {
  QueryData results;

  SQL sql("select groupname from groups");
  if (!sql.ok()) {
    LOG(WARNING) << sql.getStatus().getMessage();
  }

  for (auto row : sql.rows()) {
    genMembersOfLocalGroup(std::wstring(), row["groupname"], results, genGroupMemberRow);

  }


  return results;
}
} // namespace tables
} // namespace osquery
