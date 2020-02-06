
#pragma once

#include <memory>
#include <optional>
#include <set>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include <osquery/events/proto/events.pb.h>

namespace osquery {
class IBaseRequestOutput {
 public:
  virtual ~IBaseRequestOutput(void) = default;

  virtual bool running(void) const = 0;
  virtual void terminate(void) = 0;

  virtual Status &status(void) = 0;

  virtual bool ready() const = 0;
};

template <typename DataType>
class IBaseStreamRequestOutput
    : public IBaseRequestOutput {
 public:
  virtual ~IBaseStreamRequestOutput(void) = default;

  virtual std::vector<DataType> getData(void) = 0;
};

template <typename DataType>
class IBaseItemRequestOutput
    : public IBaseRequestOutput {
 public:
  virtual ~IBaseItemRequestOutput(void) = default;

  virtual DataType getData(void) = 0;
};

using IQueryEventRequestOutput = IBaseStreamRequestOutput<containerd::services::events::v1::Envelope>;

using IQueryEventRequestOutputRef =
    std::shared_ptr<IQueryEventRequestOutput>;

class IAsyncAPIClient {
 public:
  virtual ~IAsyncAPIClient(void) = default;

  virtual IQueryEventRequestOutputRef SubscribeEvents(
      const containerd::services::events::v1::SubscribeRequest &subscribe_request) const = 0;
};

using IAsyncAPIClientRef = std::shared_ptr<IAsyncAPIClient>;

Status CreateAsyncAPIClient(
    IAsyncAPIClientRef &obj, const std::string &address);
}  // namespace mu
