
#pragma once

#include <atomic>
#include <future>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "client_interface.h"

#include <grpcpp/grpcpp.h>

namespace osquery {

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
class BaseRequest final {
 public:
  class Output final : public IBaseStreamRequestOutput<RPCOutput> {
    struct PrivateData;
    std::unique_ptr<PrivateData> d;

   public:
    Output(void);
    virtual ~Output(void);

    virtual bool running(void) const override;
    virtual void terminate(void) override;

    virtual bool ready() const override;

    virtual Status &status(void) override;
    virtual std::vector<RPCOutput> getData(void) override;

   private:
    std::atomic_bool &getTerminateFlagRef(void);
    void setFutureStatus(Status status);
    virtual void addData(const RPCOutput &item);

    friend class AsyncAPIClient;
    friend class BaseRequest<ServiceClass, RPCInput, RPCOutput>;
  };

  enum class RequestTag { Events };

  using OutputRef =
      std::shared_ptr<BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output>;

  using ClientAsyncReaderInterface =
      grpc::ClientAsyncReaderInterface<RPCOutput>;

  using ClientAsyncReaderInterfaceRef =
      std::unique_ptr<ClientAsyncReaderInterface>;

  using RPCFactory = ClientAsyncReaderInterfaceRef (
      ServiceClass::StubInterface::*)(
      grpc::ClientContext *, const RPCInput &, grpc::CompletionQueue *);

  static std::shared_ptr<IBaseStreamRequestOutput<RPCOutput>> create(
      const std::string &address, RPCFactory rpc_factory,
      const RPCInput &input_parameters);

  BaseRequest(RPCFactory rpc_factory, const RPCInput &input,
      const std::string &address, std::atomic_bool &terminate);

  ~BaseRequest(void);

  std::atomic_bool &getTerminateFlagRef(void);
  Status execute(Output &output);

 protected:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Status processNextEvent(RequestTag current_tag, bool succeeded,
      ClientAsyncReaderInterface &response_reader, Output &output);
};

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
struct BaseRequest<ServiceClass, RPCInput, RPCOutput>::PrivateData final {
  PrivateData(std::atomic_bool &terminate_) : terminate(terminate_) {}

  std::atomic_bool &terminate;

  RPCFactory rpc_factory;
  RPCInput rpc_input;
  std::string address;

  RPCOutput current_item;
  grpc::Status grpc_status;
};

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
std::shared_ptr<IBaseStreamRequestOutput<RPCOutput>>
BaseRequest<ServiceClass, RPCInput, RPCOutput>::create(
    const std::string &address, RPCFactory rpc_factory,
    const RPCInput &input_parameters) {
  // clang-format off
  static auto L_worker = [](RPCFactory rpc_factory,
                            RPCInput input_parameters,
                            Output &output,
                            const std::string &address) -> Status {

    BaseRequest<ServiceClass, RPCInput, RPCOutput> request(
      rpc_factory, input_parameters, address,
      output.getTerminateFlagRef()
    );

    return request.execute(output);
  };
  // clang-format on

  auto output = new BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output();
  std::shared_ptr<IBaseStreamRequestOutput<RPCOutput>> output_ref(output);

  auto status = std::async(
      L_worker, rpc_factory, input_parameters, std::ref(*output), address);

  //output->setFutureStatus(std::move(status));
  return output_ref;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
BaseRequest<ServiceClass, RPCInput, RPCOutput>::BaseRequest(
    RPCFactory rpc_factory, const RPCInput &rpc_input,
    const std::string &address, std::atomic_bool &terminate)
    : d(new PrivateData(terminate)) {

  d->rpc_factory = rpc_factory;
  d->rpc_input = rpc_input;
  d->address = address;
  d->terminate = false;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
BaseRequest<ServiceClass, RPCInput, RPCOutput>::~BaseRequest(void) {}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
std::atomic_bool &
BaseRequest<ServiceClass, RPCInput, RPCOutput>::getTerminateFlagRef(void) {
  return d->terminate;
}

// Create the stub for communication
template <typename ServiceClass, typename RPCInput, typename RPCOutput>
Status BaseRequest<ServiceClass, RPCInput, RPCOutput>::execute(Output &output) {
  auto channel =
      grpc::CreateChannel(d->address, grpc::InsecureChannelCredentials());

  auto stub = ServiceClass::NewStub(channel);

  grpc::ClientContext client_context;
  grpc::CompletionQueue completion_queue;

  auto response_reader = (*stub.get().*d->rpc_factory)(
      &client_context, d->rpc_input, &completion_queue);

  response_reader->StartCall(reinterpret_cast<void *>(RequestTag::Events));

  bool request_aborted = false;
  Status status;

  for (;;) {
    if (d->terminate) {
      client_context.TryCancel();
      request_aborted = true;
    }

    void *current_raw_tag = nullptr;
    bool succeeded = false;
    auto timeout = std::chrono::system_clock::now() + std::chrono::seconds(1);

    auto s = completion_queue.AsyncNext(&current_raw_tag, &succeeded, timeout);
    if (s == grpc::CompletionQueue::SHUTDOWN) {
      request_aborted = true;
      break;

    } else if (s == grpc::CompletionQueue::TIMEOUT) {
      continue;
    }

    auto current_tag = static_cast<RequestTag>(
        reinterpret_cast<std::int64_t>(current_raw_tag));

    if (current_tag == RequestTag::Events && !succeeded) {
      return Status(false, "Failed to initialize the RPC call");
    }

    status = processNextEvent(
        current_tag, succeeded, *response_reader.get(), output);
    if (!status) {
      return status;
    }

    if (current_tag == RequestTag::Events) {
      break;
    }
  }

  if (request_aborted) {
    return Status(false, "The request was aborted");
  }

  return status;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
Status BaseRequest<ServiceClass, RPCInput, RPCOutput>::processNextEvent(
    RequestTag current_tag, bool succeeded,
    ClientAsyncReaderInterface &response_reader, Output &output) {
  if (current_tag == RequestTag::Events) {
    if (!succeeded) {
      return Status(false, "Failed to initialize the RPC call");
    }

    response_reader.Read(
        &d->current_item, reinterpret_cast<void *>(RequestTag::Events));

    return Status(true);

  } else if (current_tag == RequestTag::Events) {
    bool terminate = false;

    if (succeeded) {
      output.addData(d->current_item);
    } else {
      terminate = true;
    }

    if (terminate) {
      response_reader.Finish(
          &d->grpc_status, reinterpret_cast<void *>(RequestTag::Events));
    } else {
      response_reader.Read(
          &d->current_item, reinterpret_cast<void *>(RequestTag::Events));
    }

    return Status(true);

  } else if (current_tag == RequestTag::Events) {
    if (!d->grpc_status.ok()) {
      return Status(false, "gRPC error");
    }

    return Status(true);

  } else {
    return Status(false, "Invalid event received");
  }
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
struct BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::PrivateData
    final {
  Status status;
  std::atomic_bool terminate{false};

  mutable std::mutex item_list_mutex;
  std::vector<RPCOutput> item_list;
};

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::Output(void)
    : d(new PrivateData) {}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::~Output(void) {
/*  if (d->status.valid()) {
    d->terminate = true;
    d->status.wait();
  }*/
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
bool BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::running(
    void) const {
  /*switch (d->status.wait_for(std::chrono::seconds(0U))) {
    case std::future_status::timeout:
    case std::future_status::deferred:
      return true;

    case std::future_status::ready:
      return false;
  }*/
  return true;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
void BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::terminate(void) {
  d->terminate = true;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
bool BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::ready(void) const {
  bool readable = false;

  {
    std::lock_guard<std::mutex> lock(d->item_list_mutex);
    readable = !d->item_list.empty();
  }

  return readable;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
Status
    &BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::status(void) {
  return d->status;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
std::vector<RPCOutput>
BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::getData(void) {
  std::vector<RPCOutput> item_list;

  {
    std::lock_guard<std::mutex> lock(d->item_list_mutex);

    item_list = std::move(d->item_list);
    d->item_list.clear();
  }

  return item_list;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
void BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::addData(
    const RPCOutput &item) {
  std::lock_guard<std::mutex> lock(d->item_list_mutex);
  d->item_list.push_back(item);
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
std::atomic_bool &
BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::getTerminateFlagRef(
    void) {
  return d->terminate;
}

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
void BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output::setFutureStatus(
    Status status) {
  d->status = std::move(status);
}
}  // namespace mu
