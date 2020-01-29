/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/containereventpublisher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {

REGISTER(ContainerEventPublisher, "event_publisher", "containerevent");

Status ContainerEventPublisher::setUp() {
  LOG(ERROR) << "ContainerEventPublisher::setUp called\n";
  return Status::success();
}

void ContainerEventPublisher::configure() {
  LOG(ERROR) << "ContainerEventPublisher::configure called\n";
}

void ContainerEventPublisher::tearDown() {
  LOG(ERROR) << "ContainerEventPublisher::tearDown called\n";
}

Status ContainerEventPublisher::run() {
  LOG(ERROR) << "ContainerEventPublisher::run called\n";
  return Status::success();
}

} // namespace osquery

