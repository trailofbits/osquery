/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpfnetworkeventstable.h"
#include "networkeventsservice.h"

#include <osquery/experiments/bpf_network_events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

void initializeBpfNetworkEvents() {
  auto table_exp = BPFNetworkEventsTable::create();
  if (table_exp.isError()) {
    LOG(ERROR) << "Failed to initialize the bpf_network_events table: "
               << table_exp.getError().getMessage();

    return;
  }

  auto table = table_exp.take();

  auto registry = RegistryFactory::get().registry("table");
  registry->add(table->name(), table);

  Registry::call(
      "sql", "sql", {{"action", "attach"}, {"table", table->name()}});

  Dispatcher::addService(std::make_shared<NetworkEventsService>(*table.get()));
}

} // namespace osquery
