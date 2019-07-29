/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/system.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/system.h>

#include <osquery/process/windows/process_ops.h>

#include "osquery/tables/system/windows/groups.h"
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
std::string psidToString(PSID sid);

namespace tables {

Row getDomainGlobalGroupRow(
    const std::string& groupname,
    const std::wstring& servername,
    PGROUP_INFO_3 groupInfo) {

  Row r;
  r["groupname"] = groupname;
  r["domain"] = wstringToString(servername.c_str());
  r["group_sid"] = psidToString(groupInfo->grpi3_group_sid);
  r["comment"] = wstringToString(groupInfo->grpi3_comment);
  r["scope"] = "Global";

  return r;
}

Status genDomainGlobalGroup(const std::wstring& servername,
                    const std::string& groupname,
                    QueryData& results) {
  LPBYTE groupInfoBuf = nullptr;
  const DWORD infoLevel = 3;
  auto ret = NetGroupGetInfo(
                servername.c_str(),
                stringToWstring(groupname).c_str(),
                infoLevel,
                &groupInfoBuf);

  if (ret != NERR_Success || groupInfoBuf == nullptr) {
    LOG(INFO) << "NetGroupGetInfo failed with return value: " << ret;
    return Status::failure("NetGroupGetInfo failed");
  }

  auto groupInfo = PGROUP_INFO_3(groupInfoBuf);
  Row r = getDomainGlobalGroupRow(groupname, servername, groupInfo);
  results.push_back(r);

  NetApiBufferFree(groupInfoBuf);

  return Status::success();
}

Status getDomainLocalGroupRow(
    const std::string& groupname,
    const std::wstring& servername,
    LPLOCALGROUP_INFO_1 groupInfo,
    Row& r) {

  r["groupname"] = groupname;
  r["domain"] = wstringToString(servername.c_str());
  r["comment"] = wstringToString(groupInfo->lgrpi1_comment);
  r["scope"] = "Domain local";

  auto sidSmartPtr = getSidFromUsername(stringToWstring(groupname).c_str(), servername.c_str());
  if (sidSmartPtr == nullptr) {
    return Status::failure("Failed to find a SID for group: " + groupname);
  } else {
    auto sidPtr = static_cast<PSID>(sidSmartPtr.get());
    r["group_sid"] = psidToString(sidPtr);
  }

  return Status::success();
}

Status genDomainLocalGroup(const std::wstring& servername,
                    const std::string& groupname,
                    QueryData& results) {
  LPBYTE groupInfoBuf = nullptr;
  const DWORD infoLevel = 1;
  auto ret = NetLocalGroupGetInfo(
                servername.c_str(),
                stringToWstring(groupname).c_str(),
                infoLevel,
                &groupInfoBuf);

  if (ret != NERR_Success || groupInfoBuf == nullptr) {
    LOG(INFO) << "NetLocalGroupGetInfo failed with return value: " << ret;
    return Status::failure("NetLocalGroupGetInfo failed");
  }

  auto groupInfo = LPLOCALGROUP_INFO_1(groupInfoBuf);
  Row r;
  auto gotGroup = getDomainLocalGroupRow(groupname, servername, groupInfo, r);
  if (gotGroup.ok()) {
    results.push_back(r);
  }

  NetApiBufferFree(groupInfoBuf);

  return Status::success();
}

void genDomainGroup(const std::wstring& servername,
                    const std::string& groupname,
                    QueryData& results) {
  auto ret = genDomainLocalGroup(servername, groupname, results);
  if (ret.ok()) {
    return;
  }
  genDomainGlobalGroup(servername, groupname, results);
}

void processDomainGlobalGroups(std::wstring& domainNameW, QueryData& results) {
	PNET_DISPLAY_GROUP groupBuffer = nullptr;
	DWORD numGroupsRead, idx = 0;
  NET_API_STATUS ret = 0;

	// if domainName is null, do nothing then?
  if (domainNameW.empty()) {
    return;
  }

	do {
    const DWORD GROUP_ACCOUNT_LEVEL = 3;
	 	ret = NetQueryDisplayInformation(domainNameW.c_str(),
                                     GROUP_ACCOUNT_LEVEL,
                                     idx,
                                     1000,
                                     MAX_PREFERRED_LENGTH,
                                     &numGroupsRead,
                                     (PVOID*) &groupBuffer);

    if (groupBuffer == nullptr || (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA)) {
      LOG(INFO) << "NetQueryDisplayInformation failed with return value: " << ret;
      break;
    }

    for (DWORD i = 0; i < numGroupsRead; i++) {
      Row row;
      auto ret = getGroupRow(domainNameW, groupBuffer[i].grpi3_name,
                             groupBuffer[i].grpi3_comment, "Global", row);

      // Only add a row if we successfully created one
      if (ret.ok()) {
        results.push_back(row);
      }

      idx = groupBuffer[i].grpi3_next_index;
    }

    NetApiBufferFree(groupBuffer);

	} while (ret == ERROR_MORE_DATA);
}

void genDomainGroupFromSid(const std::wstring& domainName,
                           const std::string& sidString,
                           QueryData& results) {
  auto username = getUsernameFromSid(sidString);
  genDomainGroup(domainName, username, results);
}

QueryData genDomainGroups(QueryContext& context) {
  QueryData results;

  std::cout << "genDomainGroups\n";

  auto domainName = getWinDomainName();

  if (context.constraints["groupname"].exists(EQUALS)) {
    auto groupnames = context.constraints["groupname"].getAll(EQUALS);
    for (const auto& groupname : groupnames) {
      genDomainGroup(domainName, groupname, results);
    }
  } else if (context.constraints["group_sid"].exists(EQUALS)) {
    auto groupnames = context.constraints["group_sid"].getAll(EQUALS);
    for (const auto& sid : groupnames) {
      genDomainGroupFromSid(domainName, sid, results);
    }

  } else {
    processGroups(domainName, results, true);
    processDomainGlobalGroups(domainName, results);
  }

  return results;
}
}
}

