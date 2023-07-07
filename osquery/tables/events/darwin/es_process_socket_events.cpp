/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Availability.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <os/availability.h>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/events.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

REGISTER(ESProcessSocketEventSubscriber,
         "event_subscriber",
         "es_process_socket_events");

Status ESProcessSocketEventSubscriber::init() {
  if (__builtin_available(macos 10.15, *)) {
    auto sc = createSubscriptionContext();

    sc->es_socket_event_subscriptions_.push_back(
        ES_EVENT_TYPE_NOTIFY_UIPC_BIND);
    sc->es_socket_event_subscriptions_.push_back(
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT);

    subscribe(&ESProcessSocketEventSubscriber::Callback, sc);

    return Status::success();
  } else {
    return Status::failure(1, "Only available on macOS 10.15 and higher");
  }
}

Status ESProcessSocketEventSubscriber::Callback(
    const EndpointSecuritySocketEventContextRef& ec,
    const EndpointSecuritySocketSubscriptionContextRef& sc) {
  Row r;

  r["version"] = INTEGER(ec->version);
  r["seq_num"] = BIGINT(ec->seq_num);
  r["global_seq_num"] = BIGINT(ec->global_seq_num);

  r["event_type"] = ec->event_type;

  r["pid"] = BIGINT(ec->pid);
  r["parent"] = BIGINT(ec->parent);

  r["path"] = ec->path;

  r["family"] = INTEGER(ec->domain);
  r["protocol"] = INTEGER(ec->protocol);
  r["type"] = INTEGER(ec->type);
  r["socket"] = SQL_TEXT(ec->socket_path);

  sc->row_list = {r};
  if (!sc->row_list.empty()) {
    addBatch(sc->row_list);
  }

  return Status::success();
}
} // namespace osquery
