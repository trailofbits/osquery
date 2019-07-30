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
uint32_t getGidFromSid(PSID sid);

namespace tables {

Status genFlatDomainUserGlobalGroupRow(
    const std::wstring& domain,
    const std::string& original_groupname,
    const std::string& originalGroupSidString,
    std::string& path,
    GROUP_USERS_INFO_0& member,
    Row& r) {
  std::string sidString;
  auto ret = accountNameToSidString(wstringToString(member.grui0_name), domain, sidString);
  if (ret.ok()) {
    r["member_sid"] = sidString;
  }

  r["membername"] = wstringToString(member.grui0_name);

  std::cout << "adding row for : " <<  wstringToString(member.grui0_name) << "\n";

  std::cout << "setting original_groupname to " << original_groupname << "\n";
  r["groupname"] = original_groupname;
  r["path"] = path;
  r["domain"] = wstringToString(domain.c_str());

  r["group_sid"] = originalGroupSidString;

  /* auto sidSmartPtr =
   * getSidFromUsername(stringToWstring(original_groupname).c_str(),
   * domain.c_str()); */
  /* if (sidSmartPtr == nullptr) { */
  /*   return Status::failure("Failed to find a SID for group: " +
   * original_groupname); */
  /* } else { */
  /*   auto sidPtr = static_cast<PSID>(sidSmartPtr.get()); */
  /*   r["group_sid"] = psidToString(sidPtr); */
  /* } */

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
    std::unordered_set<std::string>& visited_groups,
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

    if (depth == 0 && domain.empty()) {
      auto domain = getWinDomainName();
      std::cout << "trying harder with domain\n";

      auto newret = genFlatMembersOfLocalGroup(domain,
                                               groupname,
                                               original,
                                               path,
                                               results,
                                               visited_groups,
                                               depth + 1);

      return newret;
    }

    return Status::failure("Fail to look up local group");
  }

  std::string originalGroupSidString;

  // Don't use domain because original group is local?
  /* auto sidSmartPtr = getSidFromUsername(stringToWstring(original).c_str(),
   * domain.c_str()); */
  auto sidSmartPtr =
      getSidFromUsername(stringToWstring(original).c_str(), nullptr);
  if (sidSmartPtr != nullptr) {
    auto sidPtr = static_cast<PSID>(sidSmartPtr.get());
    originalGroupSidString = psidToString(sidPtr);
  }
  /* } else { */
  /* // we couldn't get a sid? */
  /* // that's pretty weird, and pretty bad because we use sids to keep track */
  /* // of cycles in the graph. */
  /* // we should definitely have a sid here, it's */
  /* return Status::failure(1, "failed to get sid for original group"); */
  /* } */

  std::string groupSidString;
  auto sidSmartPtr2 =
      getSidFromUsername(stringToWstring(groupname).c_str(), domain.c_str());
  if (sidSmartPtr2 != nullptr) {
    auto sidPtr = static_cast<PSID>(sidSmartPtr2.get());
    groupSidString = psidToString(sidPtr);
  } else {
    // we couldn't get a sid?
    // that's pretty weird, and pretty bad because we use sids to keep track
    // of cycles in the graph.
    // we should definitely have a sid here, it's
    return Status::failure(1, "failed to get sid for group");
  }

  // mark this group as visited
  visited_groups.insert(groupSidString);
  std::cout << "added to visited " << groupSidString;

  std::cout << "numMembersRead " << numMembersRead << "\n";
  std::cout << "numMembersTotal " << numMembersTotal << "\n";

  auto groupMembers = LPLOCALGROUP_MEMBERS_INFO_1(infoBuf);

  for (DWORD i = 0; i < numMembersRead; i++) {
    auto& member = groupMembers[i];
    auto usage = member.lgrmi1_sidusage;

    // Non-builtin domain local groups are SidTypeAlias
    auto is_group_type = (usage == SidTypeGroup) ||
                         (usage == SidTypeWellKnownGroup) ||
                         (usage == SidTypeAlias);

    std::cout << "member name:" << wstringToString(member.lgrmi1_name) << "\n";

    std::string memberSid;
    auto sidSmartPtr2 = getSidFromUsername(member.lgrmi1_name, domain.c_str());
    if (sidSmartPtr2 != nullptr) {
      auto sidPtr = static_cast<PSID>(sidSmartPtr2.get());
      memberSid = psidToString(sidPtr);
    }

    std::cout << "checking if in visited " << memberSid << "\n";
    auto visited = visited_groups.count(memberSid) == 1;

#define XX(thing)                                                              \
  case thing:                                                                  \
    std::cout << #thing << "\n";                                               \
    break

    switch (usage) {
      XX(SidTypeUser);
      XX(SidTypeGroup);
      XX(SidTypeDomain);
      XX(SidTypeAlias);
      XX(SidTypeWellKnownGroup);
      XX(SidTypeDeletedAccount);
      XX(SidTypeInvalid);
      XX(SidTypeUnknown);
      XX(SidTypeComputer);
      XX(SidTypeLabel);
      XX(SidTypeLogonSession);

    default:
      break;
    }

    std::cout << "is_group_type " << is_group_type << "\n";
    std::cout << "usage " << usage << "\n";
    std::cout << "!visited " << !visited << "\n";
    std::cout << "member.lgrmi1_name " << wstringToString(member.lgrmi1_name)
              << "\n";

    if (is_group_type) {
      if (!visited) {
        auto gname = member.lgrmi1_name;

        std::cout << "recursing on " << wstringToString(gname) << "\n";
        genFlatMembersOfGroup(domain,
                              wstringToString(gname),
                              original,
                              path + "/" + wstringToString(gname),
                              results,
                              visited_groups,
                              0);
      }

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
    std::unordered_set<std::string>& visited_groups,
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

    if (depth == 0 && domain.empty()) {
      auto domain = getWinDomainName();
      std::cout << "trying harder with domain\n";

      auto newret = genFlatMembersOfGlobalGroup(domain,
                                                groupname,
                                                original,
                                                path,
                                                results,
                                                visited_groups,
                                                depth + 1);

      return newret;
    }

    return Status::failure("Fail to look up global group");
  }

  std::string originalGroupSidString;

  /* auto sidSmartPtr = getSidFromUsername(stringToWstring(original).c_str(),
   * domain.c_str()); */
  auto sidSmartPtr2 =
      getSidFromUsername(stringToWstring(original).c_str(), nullptr);
  if (sidSmartPtr2 != nullptr) {
    auto sidPtr = static_cast<PSID>(sidSmartPtr2.get());
    originalGroupSidString = psidToString(sidPtr);
  }

  std::string groupSidString;

  auto sidSmartPtr =
      getSidFromUsername(stringToWstring(groupname).c_str(), domain.c_str());
  if (sidSmartPtr != nullptr) {
    auto sidPtr = static_cast<PSID>(sidSmartPtr.get());
    groupSidString = psidToString(sidPtr);
  } else {
    // we couldn't get a sid?
    // that's pretty weird, and pretty bad because we use sids to keep track
    // of cycles in the graph.
    // we should definitely have a sid here, it's
    return Status::failure(1, "failed to get sid for group");
  }

  // mark this group as visited
  visited_groups.insert(groupSidString);
  std::cout << "added to visited " << groupSidString;

  auto groupMembers = LPGROUP_USERS_INFO_0(infoBuf);

  for (DWORD i = 0; i < numMembersRead; i++) {
    auto& member = groupMembers[i];

      Row r;
      auto gotRow = genFlatDomainUserGlobalGroupRow(
          domain, original, originalGroupSidString, path, member, r);
      if (gotRow.ok()) {
        std::cout << "pushing back!\n";
        results.push_back(r);
      }


  }


  NetApiBufferFree(infoBuf);

  return Status::success();
}

void genFlatMembersOfGroup(const std::wstring& domain,
                           const std::string& groupname,
                           const std::string& original_groupname,
                           std::string& path,
                           QueryData& results,
                           std::unordered_set<std::string>& visited_groups,
                           int depth

) {
  auto ret = genFlatMembersOfLocalGroup(domain,
                                        groupname,
                                        original_groupname,
                                        path,
                                        results,
                                        visited_groups,
                                        depth);
  /* auto ret = genFlatMembersOfLocalGroup(domain, groupname,
   * original_groupname, path, results, depth); */
  if (ret.ok()) {
    return;
  }
  genFlatMembersOfGlobalGroup(domain,
                              groupname,
                              original_groupname,
                              path,
                              results,
                              visited_groups,
                              depth);
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

  std::unordered_set<std::string> visited_groups;

  auto groupnames = context.constraints["groupname"].getAll(EQUALS);
  for (auto& groupname : groupnames) {
    auto path = groupname;
    genFlatMembersOfGroup(
        std::wstring(), groupname, groupname, path, results, visited_groups, 0);
    /* genFlatMembersOfGroup(std::wstring(), groupname, groupname, path,
     * results, 0); */
  }

  return results;

}
} // namespace tables
} // namespace osquery
