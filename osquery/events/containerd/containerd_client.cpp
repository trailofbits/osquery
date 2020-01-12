/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <mutex>
#include <vector>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include <osquery/events/containerd/events.grpc.pb.h>

#include "base_request.h"
#include "client_interface.h"
#include "containerd_client.h"

namespace osquery {

using QueryEventRequest =
    BaseRequest<::containerd::services::events::v1::Events,
                ::containerd::services::events::v1::SubscribeRequest,
                ::containerd::services::events::v1::Envelope>;

struct ContainerdAsyncAPIClient::PrivateData final {
  std::string address;
};

ContainerdAsyncAPIClient::ContainerdAsyncAPIClient(const std::string& address)
    : d(new PrivateData) {
  d->address = address;
}

ContainerdAsyncAPIClient::~ContainerdAsyncAPIClient(void) {}

IQueryEventRequestOutputRef ContainerdAsyncAPIClient::subscribeEvents(
    const containerd::services::events::v1::SubscribeRequest& subscribe_request)
    const {
  return QueryEventRequest::create(d->address,
                                   &containerd::services::events::v1::Events::
                                       StubInterface::PrepareAsyncSubscribe,
                                   subscribe_request);
}

Status createAsyncAPIClient(IAsyncAPIClientRef& obj,
                            const std::string& address) {
  try {
    obj.reset();

    IAsyncAPIClientRef client_ref(new ContainerdAsyncAPIClient(address));
    obj = client_ref;

    return Status::success();

  } catch (const std::bad_alloc&) {
    return Status::failure("Memory allocation failure");

  } catch (const Status& status) {
    return status;
  }
}

} // namespace osquery
