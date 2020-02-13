/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <limits>
#include <memory>

#include <boost/variant.hpp>

#include <osquery/events.h>

#include <osquery/events/client/client_interface.h>

namespace osquery {

struct ContainerEventData final {
  std::uint64_t timestamp;

  std::string event;
  std::string container_id;
  std::string image_name;
};

/// Audit event descriptor
struct ContainerEvent final {
  enum class Type { ContainerEvent, ImageEvent, PluginEvent };

  Type type;
  ContainerEventData data;
};


struct ContainerSubscriptionContext final : public SubscriptionContext {
 private:
  friend class ContainerEventPublisher;
};

struct ContainerEventContext final : public EventContext {
  std::vector<ContainerEvent> container_events;
};

class ContainerEventPublisher final
: public EventPublisher<ContainerSubscriptionContext, ContainerEventContext> {
  DECLARE_PUBLISHER("containerevent");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;

  virtual ~ContainerEventPublisher() {
    tearDown();
  }

 private:

  IAsyncAPIClientRef rpc_client;

  std::string socket_addr;
};

} // namespace osquery
