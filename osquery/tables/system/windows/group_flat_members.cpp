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
#include "osquery/tables/system/windows/domain_user_groups.h"
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/process/process.h>
#include <osquery/process/windows/process_ops.h>

namespace osquery {

std::string psidToString(PSID sid);
int getGidFromSid(PSID sid);

namespace tables {

Status genFlatDomainUserGlobalGroupRow(
    const std::wstring& domain,
    const std::string& groupname,
    std::string& path,
    GROUP_USERS_INFO_0& member,
    Row& r
    ) {

  std::string sidString;
  auto ret = accountNameToSidString(wstringToString(member.grui0_name), domain, sidString);
  if (ret.ok()) {
    r["member_sid"] = sidString;
  }

  r["membername"] = wstringToString(member.grui0_name);

  std::cout << "adding row for : " <<  wstringToString(member.grui0_name) << "\n";


  std::cout << "setting groupname to " << groupname << "\n";
  r["groupname"] = groupname;
  r["path"] = path;
  r["domain"] = wstringToString(domain.c_str());

  auto sidSmartPtr = getSidFromUsername(stringToWstring(groupname).c_str(), domain.c_str());
  if (sidSmartPtr == nullptr) {
    return Status::failure("Failed to find a SID for group: " + groupname);
  } else {
    auto sidPtr = static_cast<PSID>(sidSmartPtr.get());
    r["group_sid"] = psidToString(sidPtr);
  }

  return Status::success();
}



Status genFlatDomainUserLocalGroupRow(
    const std::wstring& domain,
    const std::string& groupname,
    const std::string& groupSid,
    const std::string& path,
    LOCALGROUP_MEMBERS_INFO_1& member,
    Row& r
    ) {

  r["member_sid"] = psidToString(member.lgrmi1_sid);
  r["membername"] = wstringToString(member.lgrmi1_name);

  std::cout << "adding row for : " <<  wstringToString(member.lgrmi1_name) << "\n";


  r["groupname"] = groupname;
  r["path"] = path;
  r["domain"] = wstringToString(domain.c_str());

  r["group_sid"] = groupSid;

  return Status::success();
}

Status genFlatMembersOfLocalGroup(
    const std::wstring& domain,
    const std::string& groupname,
    const std::string& original,
    std::string& path,
    QueryData& results,
    int depth
    
    ) {

  const DWORD infoLevel = 1; // Get SID and Name
  LPBYTE infoBuf = nullptr;
  DWORD numMembersRead = 0;
  DWORD numMembersTotal = 0;
  DWORD_PTR resumeHandle = 0;

  std::cout << "genFlatMembersOfLocalGroup : " << groupname << "\n";
  std::cout << "depth : " << depth << "\n";

  auto ret = NetLocalGroupGetMembers(
              domain.c_str(),
              stringToWstring(groupname).c_str(),
              infoLevel,
              &infoBuf,
              MAX_PREFERRED_LENGTH,
              &numMembersRead,
              &numMembersTotal,
              &resumeHandle
             );

  if (ret != NERR_Success || infoBuf == nullptr) {
    std::cout << "fail to look up group\n";

    if (depth == 0) {

      auto domain = getWinDomainName();
      std::cout << "trying harder with domain\n";


      auto newret = genFlatMembersOfLocalGroup(domain, groupname, original, path, results, depth+1);

      return newret;

    }

    return Status::failure("Fail to look up local group");
  }

  // TODO compute the group sid here rather than calculating it 
  std::string originalGroupSidString;

  auto sidSmartPtr = getSidFromUsername(stringToWstring(original).c_str(), domain.c_str());
  if (sidSmartPtr != nullptr) {
    auto sidPtr = static_cast<PSID>(sidSmartPtr.get());
    originalGroupSidString = psidToString(sidPtr);
  }

  std::cout << "numMembersRead " << numMembersRead << "\n";
  std::cout << "numMembersTotal " << numMembersTotal << "\n";

  auto groupMembers = LPLOCALGROUP_MEMBERS_INFO_1(infoBuf);

  for (DWORD i = 0; i < numMembersRead; i++) {
    auto& member = groupMembers[i];
    auto usage = member.lgrmi1_sidusage;

    if (usage == SidTypeGroup || usage == SidTypeWellKnownGroup) {

      auto gname = member.lgrmi1_name;

      std::cout << "recursing on " << wstringToString(gname) << "\n";
      genFlatMembersOfGroup(domain, wstringToString(gname), original, path + "/" + wstringToString(gname),results, 0);

    } else {
      Row r;
      // should be a user
      auto gotRow = genFlatDomainUserLocalGroupRow(domain, original, originalGroupSidString, path, member, r);
      if (gotRow.ok()) {
        results.push_back(r);
      }

    }

  }


  NetApiBufferFree(infoBuf);

  return Status::success();
}

Status genFlatMembersOfGlobalGroup(
    const std::wstring& domain,
    const std::string& groupname,
    const std::string& original,
    std::string& path,
    QueryData& results,
    int depth
    
    ) {

  const DWORD infoLevel = 0; // Can only get name
  LPBYTE infoBuf = nullptr;
  DWORD numMembersRead = 0;
  DWORD numMembersTotal = 0;
  DWORD_PTR resumeHandle = 0;

  std::cout << "genFlatMembersOfGlobalGroup : " << groupname << "\n";
  std::cout << "depth : " << depth << "\n";

  auto ret = NetGroupGetUsers(
              domain.c_str(),
              stringToWstring(groupname).c_str(),
              infoLevel,
              &infoBuf,
              MAX_PREFERRED_LENGTH,
              &numMembersRead,
              &numMembersTotal,
              &resumeHandle
             );

  if (ret != NERR_Success || infoBuf == nullptr) {

    std::cout << "fail to look up global group\n";

    if (depth == 0) {

      auto domain = getWinDomainName();
      std::cout << "trying harder with domain\n";

      auto newret = genFlatMembersOfGlobalGroup(domain, groupname, original, path, results, depth+1);

      return newret;

    }

    return Status::failure("Fail to look up global group");
  }

  auto groupMembers = LPGROUP_USERS_INFO_0(infoBuf);

  for (DWORD i = 0; i < numMembersRead; i++) {
    auto& member = groupMembers[i];

      Row r;
      // should be a user
      auto gotRow = genFlatDomainUserGlobalGroupRow(domain, original, path, member,   r);
      if (gotRow.ok()) {
        std::cout << "pushing back!\n";
        results.push_back(r);
      }


  }


  NetApiBufferFree(infoBuf);

  return Status::success();
}


void genFlatMembersOfGroup(
    const std::wstring& domain,
    const std::string& groupname,
    const std::string& original_groupname,
    std::string& path,
    QueryData& results,
    int depth
    
    ) {
  auto ret = genFlatMembersOfLocalGroup(domain, groupname, original_groupname, path, results, depth);
  if (ret.ok()) {
    return;
  }
  genFlatMembersOfGlobalGroup(domain, groupname, original_groupname, path, results, depth);
}


QueryData genGroupFlatMembers(QueryContext& context) {
  QueryData results;

  if (!context.constraints["groupname"].exists(EQUALS)) {
      // error out
      return results;
  }

  // FIXME! need to handle cycles in the group graph (currently doesn't)
  // need to keep track of the groups we've already visited and check before
  // we recurse

  auto groupnames = context.constraints["groupname"].getAll(EQUALS);
  for (auto& groupname : groupnames) {
    auto path = groupname;
    genFlatMembersOfGroup(std::wstring(), groupname, groupname, path, results, 0);
  }

  return results;

}
} // namespace tables
} // namespace osquery
