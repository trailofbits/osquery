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


Status ContainerEventPublisher::setUp() {
  // Initialize the grpc library
  grpc_init();
  LOG(ERROR) << "ContainerEventPublisher::setUp called\n";
  url_events = std::string("/events");
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
  static const std::regex httpOkRegex("HTTP/1\\.(0|1) 200 OK\\\r");
  LOG(ERROR) << "ContainerEventPublisher::run called\n";

  try {
    local::stream_protocol::endpoint ep(FLAGS_container_socket);
    local::stream_protocol::iostream stream(ep);

    if (!stream) {
      LOG(ERROR) << "Error connecting to docker sock: " + stream.error().message();
    }

    stream << "GET " << url_events
        << " HTTP/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        << std::flush;

    if (stream.eof()) {
      stream.close();
      LOG(ERROR) << "Empty docker API response for: " + url_events;
    }

    // All status responses are expected to be 200
    std::string str;
    std::getline(stream, str);

    std::smatch match;
    if (!std::regex_match(str, match, httpOkRegex)) {
      stream.close();
      LOG(ERROR) << "Invalid docker API response for " + url_events + ": " + str;
      return Status(1, "Invalid docker API response for " + url_events + ": " + str);
    }

    while (!stream.eof() && str != "\r") {
      getline(stream, str);
    }

    LOG(ERROR) << "docker API response for " + url_events + ": " + str;

  } catch (const std::exception& e) {

  }

  auto event_context = createEventContext();
  fire(event_context);

  return Status::success();
}

} // namespace osquery

