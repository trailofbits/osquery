/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "networkeventsservice.h"

#include <osquery/logger/logger.h>

namespace osquery {

struct NetworkEventsService::PrivateData final {
  PrivateData(BPFNetworkEventsTable& table_) : table(table_) {}

  BPFNetworkEventsTable& table;
};

NetworkEventsService::NetworkEventsService(BPFNetworkEventsTable& table)
    : InternalRunnable("NetworkEventsService"), d(new PrivateData(table)) {}

NetworkEventsService::~NetworkEventsService() {}

void NetworkEventsService::start() {
  auto network_events_res = tob::networkevents::INetworkEvents::create();
  if (network_events_res.failed()) {
    LOG(ERROR) << "Failed to initialize the bpf_network_events service";
    return;
  }

  auto network_events = network_events_res.takeValue();

  while (!interrupted()) {
    tob::networkevents::INetworkEvents::EventList event_list = {};
    if (!network_events->exec(event_list)) {
      LOG(ERROR) << "Failed to acquire the bpf_network_events events";
      continue;
    }

    d->table.addEvents(std::move(event_list));
  }
}

void NetworkEventsService::stop() {}
} // namespace osquery
