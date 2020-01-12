/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */
#pragma once

#include <future>
#include <memory>
#include <optional>
#include <set>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/events/containerd/events.pb.h"

namespace osquery {
class IBaseRequestOutput {
 public:
  virtual ~IBaseRequestOutput(void) = default;

  virtual bool running() const = 0;
  virtual void terminate() = 0;

  virtual std::future<Status>& status() = 0;

  virtual bool ready() const = 0;
};

template <typename DataType>
class IBaseStreamRequestOutput : public IBaseRequestOutput {
 public:
  virtual ~IBaseStreamRequestOutput() = default;

  virtual std::vector<DataType> getData() = 0;
};

template <typename DataType>
class IBaseItemRequestOutput : public IBaseRequestOutput {
 public:
  virtual ~IBaseItemRequestOutput() = default;

  virtual DataType getData() = 0;
};

using IQueryEventRequestOutput =
    IBaseStreamRequestOutput<containerd::services::events::v1::Envelope>;

using IQueryEventRequestOutputRef = std::shared_ptr<IQueryEventRequestOutput>;

class IAsyncAPIClient {
 public:
  virtual ~IAsyncAPIClient() = default;

  virtual IQueryEventRequestOutputRef subscribeEvents(
      const containerd::services::events::v1::SubscribeRequest&
          subscribe_request) const = 0;
};

using IAsyncAPIClientRef = std::shared_ptr<IAsyncAPIClient>;

Status createAsyncAPIClient(IAsyncAPIClientRef& obj,
                            const std::string& address);
} // namespace osquery
