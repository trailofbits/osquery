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

#include <iostream> // del

namespace osquery {

std::string psidToString(PSID sid);
uint32_t getGidFromSid(PSID sid);

namespace tables {

Row getUserGroupRow(const std::string& uid, LPCWSTR groupname, const std::wstring& domainName,
                    const std::string& username) {
  auto sid = getSidFromUsername(groupname);
  auto gid = getGidFromSid(static_cast<PSID>(sid.get()));

  std::cout << "uid " << uid << "\n";

  Row r;
  r["uid"] = uid;
  r["gid"] = INTEGER(gid);
  return r;
}

/**
 * Local groups are enumerated for a user, and callback is executed to
 * to construct an appropriate row object for whatever table is currently
 * being generated.
 */
void processDomainUserGroups(const std::wstring& domainName,
			     std::string uid,
                             std::string user,
                             QueryData& results,
                             UserLocalGroupCallback callback
                             ) {
  unsigned long userGroupInfoLevel = 0;
  unsigned long numGroups = 0;
  unsigned long totalUserGroups = 0;
  LOCALGROUP_USERS_INFO_0* ginfo = nullptr;
  PSID sid = nullptr;

  unsigned long ret = 0;

  auto serverName = domainName.empty() ? nullptr : domainName.c_str();

  auto originalUsername = user;

  if (!domainName.empty()) {
    user = wstringToString(domainName.c_str()) + "\\" + user;
  }

  /* std::wcout << "serverName " << serverName << "\n"; */
  /* std::cout << "user " << user << "\n"; */

  ret = NetUserGetLocalGroups(serverName,
                              stringToWstring(user).c_str(),
                              userGroupInfoLevel,
                              1,
                              reinterpret_cast<LPBYTE*>(&ginfo),
                              MAX_PREFERRED_LENGTH,
                              &numGroups,
                              &totalUserGroups);
  if (ret == ERROR_MORE_DATA) {
    LOG(WARNING) << "User " << user
                 << " group membership exceeds buffer limits, processing "
                 << numGroups << " our of " << totalUserGroups << " groups";
  } else if (ret != NERR_Success || ginfo == nullptr) {
    VLOG(1) << " NetUserGetLocalGroups failed for user " << user << " with "
            << ret;
    return;
  }

  for (size_t i = 0; i < numGroups; i++) {
    Row r = callback(uid, ginfo[i].lgrui0_name, domainName, originalUsername);
    results.push_back(r);
  }

  if (ginfo != nullptr) {
    NetApiBufferFree(ginfo);
  }
}


QueryData genUserGroups(QueryContext& context) {
  QueryData results;

  SQL sql(
      "SELECT uid, username FROM users WHERE username NOT IN ('SYSTEM', "
      "'LOCAL SERVICE', 'NETWORK SERVICE')");
  if (!sql.ok()) {
    LOG(WARNING) << sql.getStatus().getMessage();
  }

  for (auto r : sql.rows()) {
    processDomainUserGroups(std::wstring(), r["uid"], r["username"], results, getUserGroupRow);
  }


  return results;
}
} // namespace tables
} // namespace osquery
