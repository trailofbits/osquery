/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "client_interface.h"

namespace osquery {

class ContainerdAsyncAPIClient final : public IAsyncAPIClient {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ContainerdAsyncAPIClient(const std::string& address);

 public:
  ~ContainerdAsyncAPIClient();

  IQueryEventRequestOutputRef subscribeEvents(
      const containerd::services::events::v1::SubscribeRequest&
          subscribe_request) const override;
  Status runEventLoop(IQueryEventRequestOutputRef output);

  ContainerdAsyncAPIClient(const ContainerdAsyncAPIClient&) = delete;
  ContainerdAsyncAPIClient& operator=(const ContainerdAsyncAPIClient&) = delete;

  friend Status createAsyncAPIClient(IAsyncAPIClientRef& obj,
                                     const std::string& address);
};
} // namespace osquery
