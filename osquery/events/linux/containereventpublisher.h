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

namespace osquery {

struct ContainerSubscriptionContext final : public SubscriptionContext {
 private:
  friend class ContainerEventPublisher;
};

struct ContainerEventContext final : public EventContext {
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
  std::string socket_addr;
  std::string url_events;

};

} // namespace osquery
