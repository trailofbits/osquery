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

#include <osquery/system.h>
#include <osquery/process/windows/process_ops.h>

#include "osquery/tables/system/windows/users.h"
#include <osquery/utils/conversions/windows/strings.h>

#include <iostream> // del this

namespace osquery {
std::string psidToString(PSID sid);

namespace tables {

Row getDomainUserRow(
    const std::string& username,
    const std::wstring& servername,
    LPUSER_INFO_4 userInfo) {
  Row r;
  r["username"] = username,
  r["description"] = wstringToString(userInfo->usri4_comment);
  r["directory"] = wstringToString(userInfo->usri4_home_dir);
  r["uuid"] = psidToString(userInfo->usri4_user_sid);
  r["domain"] = wstringToString(servername.c_str());

  return r;
}


void genDomainUser(
    const std::wstring& servername,
    const std::string& username,
                   QueryData& results) {

  LPBYTE userLvl4Buff = nullptr;
  const DWORD infoLevel = 4;
  auto ret = NetUserGetInfo(
                servername.c_str(),
                stringToWstring(username).c_str(),
                infoLevel,
                &userLvl4Buff);

  if (ret == NERR_Success) {
    auto userInfo = LPUSER_INFO_4(userLvl4Buff);
    Row r = getDomainUserRow(username, servername, userInfo);
    results.push_back(r);

    NetApiBufferFree(userLvl4Buff);
  } else {
    LOG(INFO) << "NetUserGetInfo failed with return value: " << ret;
  }
}

void genDomainUserFromSid(const std::wstring& domainName,
                          const std::string& sidString,
                          QueryData& results) {
  auto username = getUsernameFromSid(sidString);
  if (!username.empty()) {
    genDomainUser(domainName, username, results);
  }
}

QueryData genDomainUsers(QueryContext& context) {
  QueryData results;
  std::set<std::string> processedSids;

  auto domainName = getWinDomainName();
  std::wcout << L"genDomainUsers: domainName: " << domainName << L"\n";

  // TODO implement opt for uuid=? What if both username and uuid
  // are given?
  if (context.constraints["username"].exists(EQUALS)) {
    std::cout << " given username constraint!\n";
    auto usernames = context.constraints["username"].getAll(EQUALS);
    for (const auto& username : usernames) {
      /* std::cout << username << "\n"; */
      genDomainUser(domainName, username, results);
    }
  } else if (context.constraints["uuid"].exists(EQUALS)) {
    std::cout << " given uuid constraint!\n";
    auto uuids = context.constraints["uuid"].getAll(EQUALS);
    for (const auto& uuid : uuids) {
      genDomainUserFromSid(domainName, uuid, results);
    }
  } else {
    processDomainAccounts(domainName, processedSids, results);
  }



  return results;
}
}
}

