

#include <mutex>
#include <vector>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include <osquery/events/client/events.grpc.pb.h>

#include "client_interface.h"
#include "base_request.h"
#include "container_client.h"

namespace osquery {

using QueryEventRequest =
    BaseRequest<::containerd::services::events::v1::Events,
      ::containerd::services::events::v1::SubscribeRequest,
      ::containerd::services::events::v1::Envelope>;

struct AsyncAPIClient::PrivateData final {
  std::string address;
};

AsyncAPIClient::AsyncAPIClient(const std::string &address)
    : d(new PrivateData) {
  d->address = address;
}

AsyncAPIClient::~AsyncAPIClient(void) {}

IQueryEventRequestOutputRef AsyncAPIClient::SubscribeEvents(
    const containerd::services::events::v1::SubscribeRequest &subscribe_request) const {
  return QueryEventRequest::create(d->address,
                                   &containerd::services::events::v1::Events::StubInterface::PrepareAsyncSubscribe,
                                   subscribe_request);
}

Status CreateAsyncAPIClient(
    IAsyncAPIClientRef &obj, const std::string &address) {
  try {
    obj.reset();

    IAsyncAPIClientRef client_ref(new AsyncAPIClient(address));
    obj = client_ref;

    return Status(true);

  } catch (const std::bad_alloc &) {
    return Status(false, "Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

}

