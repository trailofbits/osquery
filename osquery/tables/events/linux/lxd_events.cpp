/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "lxd_events.h"

#include <osquery/registry_factory.h>
#include <osquery/utils/status/status.h>

namespace osquery {

static inline std::string default_context(void) {
  std::string default_context = "";
  return default_context;
}

REGISTER(LXDLoggingEventSubscriber, "event_subscriber", "lxd_logging_events");

Status LXDLoggingEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  sc->event_type_subscription_ = BaseLXDEvent::Type::Logging;
  subscribe(&LXDLoggingEventSubscriber::Callback, sc);

  return Status::success();
}

Status LXDLoggingEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  const auto& logging_event =
      dynamic_cast<const LXDLoggingEvent&>(*ec->lxd_event);

  r["timestamp"] = logging_event.timestamp_;
  r["location"] = logging_event.location_;
  r["level"] = logging_event.level_;
  r["message"] = logging_event.message_;

  if (logging_event.context_ != "{}") {
    r["context"] = logging_event.context_;
    deserializeRowJSON(logging_event.context_, r);
  } else {
    r["context"] = default_context();
  }

  add(r);

  return Status::success();
}

REGISTER(LXDLifecycleEventSubscriber,
         "event_subscriber",
         "lxd_lifecycle_events");

Status LXDLifecycleEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  sc->event_type_subscription_ = BaseLXDEvent::Type::Lifecyle;
  subscribe(&LXDLifecycleEventSubscriber::Callback, sc);

  return Status::success();
}

Status LXDLifecycleEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  const auto& lifecycle_event =
      dynamic_cast<const LXDLifecycleEvent&>(*ec->lxd_event);

  r["timestamp"] = lifecycle_event.timestamp_;
  r["location"] = lifecycle_event.location_;
  r["action"] = lifecycle_event.action_;
  r["source"] = lifecycle_event.source_;

  if (lifecycle_event.context_ != "{}") {
    r["context"] = lifecycle_event.context_;
    deserializeRowJSON(lifecycle_event.context_, r);
  } else {
    r["context"] = default_context();
  }

  add(r);

  return Status::success();
}

REGISTER(LXDOperationEventSubscriber,
         "event_subscriber",
         "lxd_operation_events");

Status LXDOperationEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  sc->event_type_subscription_ = BaseLXDEvent::Type::Operation;
  subscribe(&LXDOperationEventSubscriber::Callback, sc);

  return Status::success();
}

Status LXDOperationEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  const auto& operation_event =
      dynamic_cast<const LXDOperationEvent&>(*ec->lxd_event);

  r["timestamp"] = operation_event.timestamp_;
  r["location"] = operation_event.location_;
  r["id"] = operation_event.id_;
  r["class"] = operation_event.class_name_;
  r["created_at"] = operation_event.created_at_;
  r["updated_at"] = operation_event.created_at_;
  r["status"] = operation_event.status_;
  r["status_code"] = INTEGER(operation_event.status_code_);
  r["resources"] = operation_event.resources_;
  r["metdata"] = operation_event.metadata_;
  r["may_cancel"] = operation_event.may_cancel_ ? "true" : "false";
  r["error"] = operation_event.error_;

  add(r);

  return Status::success();
}
} // namespace osquery
