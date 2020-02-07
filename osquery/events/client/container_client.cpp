

#include <mutex>
#include <vector>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "client_interface.h"
#include "container_client.h"

namespace osquery {


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
  return nullptr;
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

