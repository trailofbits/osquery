/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <regex>

#include <boost/asio.hpp>

#include <grpcpp/grpcpp.h>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/events/linux/containereventpublisher.h>

namespace local = boost::asio::local;

namespace osquery {

REGISTER(ContainerEventPublisher, "event_publisher", "containerevent");

FLAG(string,
     container_socket,
     "/run/containerd/containerd.sock",
     "Docker UNIX domain socket path");


namespace {
bool IsPublisherEnabled() noexcept {
  return true;
}
} // namespace


Status ContainerEventPublisher::setUp() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Container Event Publisher disabled via configuration");
  }

  // Initialize the grpc library
  grpc_init();

  // create the async client for container
  auto status = CreateAsyncAPIClient(rpc_client, FLAGS_container_socket);
  return Status::success();
}

void ContainerEventPublisher::configure() {
  LOG(ERROR) << "ContainerEventPublisher::configure called\n";

}

void ContainerEventPublisher::tearDown() {
  LOG(ERROR) << "ContainerEventPublisher::tearDown called\n";
  grpc_shutdown();
}

Status ContainerEventPublisher::run() {
  auto event_context = createEventContext();
  fire(event_context);

  return Status::success();
}

} // namespace osquery

