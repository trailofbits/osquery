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
#include <osquery/process/process.h>
#include <osquery/process/windows/process_ops.h>

#include "osquery/tables/system/windows/registry.h"
#include "osquery/tables/system/windows/groups.h"
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

#include <iostream>

namespace osquery {

namespace tables {

// Fill out a row based on domain name, group name, and comment info
// @scope: If not empty, use this as the "scope" column
Status getGroupRow(const std::wstring& domainNameW,
                   LPCWSTR groupName,
                   LPCWSTR comment,
                   const std::string& scope,
                   Row& r) {

  std::wstring fqGroupName = groupName;

  if (!domainNameW.empty() && !fqGroupName.empty()) {
    fqGroupName = domainNameW + L"\\" + fqGroupName;
  }
  std::wcout << "fqGroupName: " << fqGroupName << "\n";
  /* std::wcout << "groupName: " << groupName << "\n"; */

  auto sidSmartPtr = getSidFromUsername(groupName, domainNameW.c_str());

  if (sidSmartPtr == nullptr) {
    return Status::failure("Failed to find a SID for group: " +  wstringToString(fqGroupName.c_str()));
  }

  auto sidPtr = static_cast<PSID>(sidSmartPtr.get());

  // Windows' extended schema, including full SID and comment strings:
  r["group_sid"] = psidToString(sidPtr);
  r["comment"] = wstringToString(comment);

  // Common schema, normalizing group information with POSIX:
  r["gid"] = INTEGER(getRidFromSid(sidPtr));
  r["gid_signed"] = INTEGER(getRidFromSid(sidPtr));
  r["groupname"] = wstringToString(groupName);
  if (!domainNameW.empty()) {
    r["domain"] = wstringToString(domainNameW.c_str());
  }
  if (!scope.empty()) {
    r["scope"] = scope;
  }

  return Status::success();
}


void processGroups(const std::wstring& domainNameW,
                   QueryData& results, bool scope_column) {
  unsigned long groupInfoLevel = 1;
  unsigned long numGroupsRead = 0;
  unsigned long totalGroups = 0;
  unsigned long resumeHandle = 0;
  unsigned long ret = 0;
  LOCALGROUP_INFO_1* lginfo = nullptr;

  std::unique_ptr<BYTE[]> sidSmartPtr = nullptr;
  PSID sidPtr = nullptr;

  auto serverName = domainNameW.empty() ? nullptr : domainNameW.c_str();
  const std::string scope = scope_column ? "Domain local" : "";

  do {
    ret = NetLocalGroupEnum(domainNameW.c_str(),
                            groupInfoLevel,
                            (LPBYTE*)&lginfo,
                            MAX_PREFERRED_LENGTH,
                            &numGroupsRead,
                            &totalGroups,
                            nullptr);

    if (lginfo == nullptr || (ret != NERR_Success && ret != ERROR_MORE_DATA)) {
      LOG(INFO) << "NetLocalGroupEnum failed with return value: " << ret;
      break;
    }

    for (size_t i = 0; i < numGroupsRead; i++) {
      Row row;
      auto ret = getGroupRow(domainNameW, lginfo[i].lgrpi1_name,
                             lginfo[i].lgrpi1_comment, scope, row);
      // Only add a row if we successfully created one
      if (ret.ok()) {
        results.push_back(row);
      }
    }

    // Free the memory allocated by NetLocalGroupEnum:
    if (lginfo != nullptr) {
      NetApiBufferFree(lginfo);
    }
  } while (ret == ERROR_MORE_DATA);
}

QueryData genGroups(QueryContext& context) {
  QueryData results;

  std::cout << "genGroups\n";

  processGroups(std::wstring(), results);

  return results;
}
} // namespace tables
} // namespace osquery
