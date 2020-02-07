
#pragma once

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "client_interface.h"

namespace osquery {

class AsyncAPIClient final : public IAsyncAPIClient {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  AsyncAPIClient(const std::string &address);

 public:
  virtual ~AsyncAPIClient(void) override;

  virtual IQueryEventRequestOutputRef SubscribeEvents(
      const containerd::services::events::v1::SubscribeRequest &subscribe_request) const override;

  AsyncAPIClient(const AsyncAPIClient &) = delete;
  AsyncAPIClient &operator=(const AsyncAPIClient &) = delete;

  friend Status CreateAsyncAPIClient(
      IAsyncAPIClientRef &obj, const std::string &address);
};

Status CreateAsyncAPIClient(
    IAsyncAPIClientRef &obj, const std::string &address);
}  // namespace mu
