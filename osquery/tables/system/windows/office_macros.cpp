/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <vector>
#include <utility>

#include <osquery/tables/system/windows/registry.h>
#include <sqlite3.h>
#include <osquery/core.h>
#include <osquery/sql.h>
#include <osquery/tables.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/logger.h>

namespace osquery {
namespace tables {

const std::string groupPolicySuffix = "\\Software\\Policies\\Microsoft\\Office\\%\\%\\Security\\VBAWarnings";
const std::string trustCenterSuffix = "\\Software\\Microsoft\\Office\\%\\%\\Security\\VBAWarnings";

Status collectSingleTextColumn(const std::string &query, std::vector<std::string> &results) {
  auto dbc = SQLiteDBManager::get();
  sqlite3_stmt* stmt = nullptr;
  auto ret = sqlite3_prepare_v2(
      dbc->db(), query.c_str(), static_cast<int>(query.size()), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    return Status(1, "Failed to prepare sql query");
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    results.push_back(SQL_TEXT(sqlite3_column_text(stmt, 0)));
  }
  
  ret = sqlite3_finalize(stmt);
  if (ret != SQLITE_OK) {
    return Status(1,
                  "Failed to finalize statement with " + std::to_string(ret));
  }

  return Status::success();
}

Status collectDualTextColumn(const std::string &query, std::vector<std::pair<std::string, std::string>> &results) {
  auto dbc = SQLiteDBManager::get();
  sqlite3_stmt* stmt = nullptr;
  auto ret = sqlite3_prepare_v2(
      dbc->db(), query.c_str(), static_cast<int>(query.size()), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    return Status(1, "Failed to prepare sql query");
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    results.push_back(std::make_pair(SQL_TEXT(sqlite3_column_text(stmt, 0)), SQL_TEXT(sqlite3_column_text(stmt, 1))));
  }
  
  ret = sqlite3_finalize(stmt);
  if (ret != SQLITE_OK) {
    return Status(1,
                  "Failed to finalize statement with " + std::to_string(ret));
  }

  return Status::success();
}

Status getSids(std::vector<std::string> &sids) {
  return collectSingleTextColumn("select uuid from users", sids);
}

QueryData genOfficeMacros(QueryContext& context) {
  QueryData results;

  std::vector<std::string> sids;
  if (context.hasConstraint("sid", EQUALS)) {
    auto provided_sids = context.constraints["sid"].getAll(EQUALS);
    sids.assign(provided_sids.begin(), provided_sids.end());
  } else {
    auto ret = getSids(sids);
    if (!ret.ok()) {
      LOG(WARNING) << "Failed to collect SIDS: " + ret.getMessage();
      return results;
    }
  }

  auto dbc = SQLiteDBManager::get();
  const std::string userQueryPrefix = "select path, data from "
                                      "registry where path like '";
  for (auto &sid : sids) {
    std::string query = userQueryPrefix + std::string("HKEY_USERS\\") + sid + groupPolicySuffix + std::string("' or path like 'HKEY_USERS\\") + sid + trustCenterSuffix + std::string("'");

    std::vector<std::pair<std::string, std::string>> entries;
    auto ret = collectDualTextColumn(query, entries);
    if (!ret.ok()) {
      LOG(INFO) << "Failed to find registry keys: " + ret.getMessage();
      continue;
    }

    for (auto &kv : entries) {
      Row r;
      auto path = kv.first;
      std::string version;
      std::string product;
      std::string stripped = path.substr(sid.length() + std::string("HKEY_USERS\\").length());
      if (std::string::npos != stripped.find("Policies")) {
        stripped = stripped.substr(std::string("Policies\\").length());
        r["policy"] = "group";
      } else {
        r["policy"] = "local";
      }
      stripped = stripped.substr(std::string("\\Software\\Microsoft\\Office\\").length());
      version = stripped.substr(0,4);
      product = stripped.substr(5, stripped.find("\\",5) - 5);
      
      r["sid"] = sid;
      r["version"] = version;
      r["product"] = product;
      r["enabled"] = kv.second;
      results.push_back(r);
    }
  }
  return results;
}

}
}
