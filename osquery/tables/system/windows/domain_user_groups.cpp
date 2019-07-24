/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <sstream>

#include <osquery/utils/system/system.h>

// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/sql.h>
#include <osquery/logger.h>

#include "osquery/tables/system/windows/user_groups.h"
#include "osquery/tables/system/windows/domain_user_groups.h"
#include <osquery/process/windows/process_ops.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/system.h>


#include <iostream> // delete this

namespace osquery {
// TODO make a header for this?
/* int getGidFromSid(PSID sid); */
uint32_t getGidFromSid(PSID sid);
std::string psidToString(PSID sid);

namespace tables {

Status accountNameToSidString(const std::string& accountName, const std::wstring& domain, std::string& sidString) {
  auto sidSmartPtr = getSidFromUsername(stringToWstring(accountName).c_str(), domain.c_str());
  if (sidSmartPtr == nullptr) {
    return Status::failure("Failed to find a SID for account: " + accountName);
  }

  auto sidPtr = static_cast<PSID>(sidSmartPtr.get());

  sidString =  psidToString(sidPtr);
  return Status::success();
}

Status genDomainUserGlobalGroupRow(
    const std::wstring& domain,
    const std::string& groupname,
    GROUP_USERS_INFO_0& member,
    Row& r
    ) {

  std::string sidString;
  auto ret = accountNameToSidString(wstringToString(member.grui0_name), domain, sidString);
  if (ret.ok()) {
    r["user_sid"] = sidString;
  }

  r["username"] = wstringToString(member.grui0_name);
  r["groupname"] = groupname;
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

Status genMembersOfGlobalGroup(
    const std::wstring& domain,
    const std::string& groupname,
    QueryData& results) {

  const DWORD infoLevel = 0; // Can only get name
  LPBYTE infoBuf = nullptr;
  DWORD numMembersRead = 0;
  DWORD numMembersTotal = 0;
  DWORD_PTR resumeHandle = 0;

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
    return Status::failure("Fail to look up global group");
  }

  auto groupMembers = LPGROUP_USERS_INFO_0(infoBuf);

  for (DWORD i = 0; i < numMembersRead; i++) {
    auto& member = groupMembers[i];
    Row r;
    auto gotRow = genDomainUserGlobalGroupRow(domain, groupname, member, r);
    if (gotRow.ok()) {
      results.push_back(r);
    }
  }

  NetApiBufferFree(infoBuf);

  return Status::success();
}

Status genDomainUserLocalGroupRow(
    const std::wstring& domain,
    const std::string& groupname,
    LOCALGROUP_MEMBERS_INFO_1& member,
    Row& r
    ) {

  r["user_sid"] = psidToString(member.lgrmi1_sid);
  r["username"] = wstringToString(member.lgrmi1_name);
  r["groupname"] = groupname;
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


/**
 * Members are enumerated for a local group, and callback is executed to
 * to construct an appropriate row object for whatever table is currently
 * being generated.
 */
Status genMembersOfLocalGroup(
    const std::wstring& domain,
    const std::string& groupname,
    QueryData& results,
    LocalGroupMemberCallback callback
    
    ) {

  const DWORD infoLevel = 1; // Get SID and Name
  LPBYTE infoBuf = nullptr;
  DWORD numMembersRead = 0;
  DWORD numMembersTotal = 0;
  DWORD_PTR resumeHandle = 0;

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
    return Status::failure("Fail to look up local group");
  }

  auto groupMembers = LPLOCALGROUP_MEMBERS_INFO_1(infoBuf);

  for (DWORD i = 0; i < numMembersRead; i++) {
    auto& member = groupMembers[i];
    Row r;
    auto gotRow = callback(domain, groupname, member, r);
    if (gotRow.ok()) {
      results.push_back(r);
    }
  }


  NetApiBufferFree(infoBuf);

  return Status::success();
}

void genMembersOfGroup(
    const std::wstring& domain,
    const std::string& groupname,
    QueryData& results) {
  auto ret = genMembersOfLocalGroup(domain, groupname, results, genDomainUserLocalGroupRow);
  if (ret.ok()) {
    return;
  }
  genMembersOfGlobalGroup(domain, groupname, results);
}


void processDomainUserGlobalGroups(const std::wstring& domainName,
	                  		           std::string uid,
                                   std::string user,
                                   QueryData& results) {
  DWORD userGroupInfoLevel = 0;
  DWORD numGroups = 0;
  DWORD totalUserGroups = 0;
  GROUP_USERS_INFO_0* ginfo = nullptr;

  if (domainName.empty()) {
    return;
  }

  /* std::wcout << "serverName " << serverName << "\n"; */
  /* std::cout << "user " << user << "\n"; */

  NET_API_STATUS ret = NetUserGetGroups(domainName.c_str(),
                                        stringToWstring(user).c_str(),
                                        userGroupInfoLevel,
                                        reinterpret_cast<LPBYTE*>(&ginfo),
                                        MAX_PREFERRED_LENGTH,
                                        &numGroups,
                                        &totalUserGroups);
  if (ret != NERR_Success || ginfo == nullptr) {
    VLOG(1) << " NetUserGetGroups failed for user " << user << " with "
            << ret;
    return;
  }

  for (DWORD i = 0; i < numGroups; i++) {
    /* std::wcout << "  group name! " << ginfo[i].grui0_name << "\n"; */
    Row r = getDomainUserGroupRow(uid, ginfo[i].grui0_name, domainName, user);
    results.push_back(r);
  }

  NetApiBufferFree(ginfo);
}

QueryData genDomainUserGroups(QueryContext& context) {
  QueryData results;

  std::cout << "genDomainUserGroups\n";

  auto domain = getWinDomainName();

  if (context.constraints["username"].exists(EQUALS)) {
    auto usernames = context.constraints["username"].getAll(EQUALS);
    for (const auto& username : usernames) {
      std::string id;
      auto ret = accountNameToSidString(username, domain, id);
      if (ret.ok()) {
        processDomainUserGroups(domain, id, username, results, getDomainUserGroupRow);
        processDomainUserGlobalGroups(domain, id, username, results);
      }
    }
    /* } else if (context.constraints["user_sid"].exists(EQUALS)) { */

  } else if (context.constraints["groupname"].exists(EQUALS)) {
    auto groupnames = context.constraints["groupname"].getAll(EQUALS);
    for (const auto& groupname : groupnames) {
      genMembersOfGroup(domain, groupname, results);
    }

  } else {
    std::stringstream queryStream;
    /* queryStream << "SELECT uid, username FROM domain_users WHERE username NOT IN ('SYSTEM', " */
    queryStream << "SELECT uuid, username FROM domain_users WHERE username NOT IN ('SYSTEM', "
                << "'LOCAL SERVICE', 'NETWORK SERVICE') AND domain = \""
                << wstringToString(domain.c_str()) << "\"";

    SQL sql(queryStream.str());
    if (!sql.ok()) {
      LOG(WARNING) << sql.getStatus().getMessage();
      LOG(WARNING) << "query was \"" << queryStream.str() << "\"";
    }

    for (auto user_row : sql.rows()) {
      processDomainUserGroups(domain, user_row["uuid"], user_row["username"], results, getDomainUserGroupRow);
      processDomainUserGlobalGroups(domain, user_row["uuid"], user_row["username"], results);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery

