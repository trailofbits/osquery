/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_bool(disable_endpointsecurity);
DECLARE_bool(disable_endpointsecurity_socketevents);

REGISTER(EndpointSecuritySocketEventPublisher,
         "event_publisher",
         "endpointsecurity_socketevents")

Status EndpointSecuritySocketEventPublisher::setUp() {
  if (__builtin_available(macos 10.15, *)) {
    if (FLAGS_disable_endpointsecurity_socketevents) {
      return Status::failure(
          1, "EndpointSecurity Socket Events is disabled via configuration");
    }

    auto handler = ^(es_client_t* client, const es_message_t* message) {
      handleMessage(message);
    };

    auto result = es_new_client(&es_socket_client_, handler);

    if (result == ES_NEW_CLIENT_RESULT_SUCCESS) {
      es_socket_client_success_ = true;
      return Status::success();
    } else {
      return Status::failure(1, getEsNewClientErrorMessage(result));
    }
  } else {
    return Status::failure(
        1, "EndpointSecurity is only available on macOS 10.15 and higher");
  }
}

void EndpointSecuritySocketEventPublisher::configure() {
  if (es_socket_client_ == nullptr) {
    return;
  }

  auto cache = es_clear_cache(es_socket_client_);
  if (cache != ES_CLEAR_CACHE_RESULT_SUCCESS) {
    VLOG(1) << "Couldn't clear cache for EndpointSecurity client";
    return;
  }

  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    auto events = sc->es_socket_event_subscriptions_;
    auto es_sub = es_subscribe(es_socket_client_, &events[0], events.size());
    if (es_sub != ES_RETURN_SUCCESS) {
      VLOG(1) << "Couldn't subscribe to EndpointSecurity subsystem";
    }
  }
}

void EndpointSecuritySocketEventPublisher::tearDown() {
  if (es_socket_client_ == nullptr) {
    return;
  }
  es_unsubscribe_all(es_socket_client_);

  if (es_socket_client_success_) {
    auto result = es_delete_client(es_socket_client_);
    if (result != ES_RETURN_SUCCESS) {
      VLOG(1) << "endpointsecurity: error tearing down es_client";
    }
    es_socket_client_ = nullptr;
  }
}

void EndpointSecuritySocketEventPublisher::handleMessage(
    const es_message_t* message) {
  if (message == nullptr) {
    return;
  }

  if (message->action_type == ES_ACTION_TYPE_AUTH) {
    return;
  }

  auto ec = createEventContext();

  ec->version = message->version;
  if (ec->version >= 2) {
    ec->seq_num = message->seq_num;
  }

  if (ec->version >= 4) {
    ec->global_seq_num = message->global_seq_num;
  }

  getProcessProperties(message->process, ec);

  switch (message->event_type) {
  case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: {
    ec->es_event = ES_EVENT_TYPE_NOTIFY_UIPC_BIND;
    ec->event_type = "bind";

    auto dir = getStringFromToken(&message->event.uipc_bind.dir->path);
    auto filename = getStringFromToken(&message->event.uipc_bind.filename);

    ec->socket_path = dir + "/" + filename;

  } break;
  case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
    ec->es_event = ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT;
    ec->event_type = "connect";

    const auto& connect_event = message->event.uipc_connect;
    ec->socket_path = getStringFromToken(&connect_event.file->path);

    ec->domain = connect_event.domain;
    ec->protocol = connect_event.protocol;
    ec->type = connect_event.type;
  } break;
  default:
    break;
  }

  EventFactory::fire<EndpointSecuritySocketEventPublisher>(ec);
}

bool EndpointSecuritySocketEventPublisher::shouldFire(
    const EndpointSecuritySocketSubscriptionContextRef& sc,
    const EndpointSecuritySocketEventContextRef& ec) const {
  return true;
}

} // namespace osquery
