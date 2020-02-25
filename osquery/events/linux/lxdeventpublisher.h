/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <future>
#include <mutex>
#include <vector>

#include <osquery/events.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/status/status.h>

#include <boost/asio.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/websocket/stream.hpp>

#if !defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
#error Boost error: Local sockets not available
#endif

namespace osquery {

namespace local = boost::asio::local;
namespace websocket = boost::beast::websocket;

class BaseLXDEvent {
 public:
  enum class Type { Logging, Operation, Lifecyle };
  BaseLXDEvent(Type type,
               const std::string& timestamp,
               const std::string& location)
      : type_(type), timestamp_(timestamp), location_(location) {}
  virtual ~BaseLXDEvent() {}

  Type type_;
  std::string timestamp_;
  std::string location_;
};

class LXDLoggingEvent final : public BaseLXDEvent {
 public:
  LXDLoggingEvent(const std::string& timestamp,
                  const std::string& location,
                  const std::string& level,
                  const std::string& message,
                  const std::string& context)
      : BaseLXDEvent(Type::Logging, timestamp, location),
        level_(level),
        message_(message),
        context_(context) {}

  std::string level_;
  std::string message_;
  std::string context_;
};

class LXDLifecycleEvent final : public BaseLXDEvent {
 public:
  LXDLifecycleEvent(const std::string& timestamp,
                    const std::string& location,
                    const std::string& action,
                    const std::string& source,
                    const std::string& context)
      : BaseLXDEvent(Type::Lifecyle, timestamp, location),
        action_(action),
        source_(source),
        context_(context) {}

  std::string action_;
  std::string source_;
  std::string context_;
};

class LXDOperationEvent final : public BaseLXDEvent {
 public:
  LXDOperationEvent(const std::string& timestamp,
                    const std::string& location,
                    const std::string& id,
                    const std::string& class_name,
                    const std::string& created_at,
                    const std::string& updated_at,
                    const std::string& status,
                    int status_code,
                    const std::string& resources,
                    const std::string& metadata,
                    bool may_cancel,
                    const std::string& error)
      : BaseLXDEvent(Type::Operation, timestamp, location),
        id_(id),
        class_name_(class_name),
        created_at_(created_at),
        updated_at_(updated_at),
        status_(status),
        status_code_(status_code),
        resources_(resources),
        metadata_(metadata),
        may_cancel_(may_cancel),
        error_(error) {}

  std::string id_;
  std::string class_name_;
  std::string created_at_;
  std::string updated_at_;
  std::string status_;
  int status_code_;
  std::string resources_;
  std::string metadata_;
  bool may_cancel_;
  std::string error_;
};

struct LXDSubscriptionContext final : public SubscriptionContext {
 public:
  BaseLXDEvent::Type event_type_subscription_;

 private:
  friend class LXDEventPublisher;
};

struct LXDEventContext final : public EventContext {
  std::unique_ptr<BaseLXDEvent> lxd_event;
};

using LXDEventContextRef = std::shared_ptr<LXDEventContext>;
using LXDSubscriptionContextRef = std::shared_ptr<LXDSubscriptionContext>;

class LXDEventPublisher final
    : public EventPublisher<LXDSubscriptionContext, LXDEventContext> {
  DECLARE_PUBLISHER("lxdevent");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;
  bool shouldFire(const LXDSubscriptionContextRef& sc,
                  const LXDEventContextRef& ec) const override;

  void cleanup();
  Status parseEvent(const std::string& event,
                    rapidjson::Document& rapidjson_doc);

  ~LXDEventPublisher() {
    tearDown();
  }

  Status readEvents();

 private:
  boost::beast::flat_buffer read_buffer_;
  std::vector<std::string> events_;
  std::future<Status> event_reader_status_;
  std::atomic<bool> interrupt_{false};
  bool running_{false};
  std::unique_ptr<
      boost::beast::websocket::stream<local::stream_protocol::socket>>
      websocket_stream_;
  boost::beast::net::io_context io_context_;
  boost::system::error_code ec_;
  std::mutex publisher_mutex_;
};

} // namespace osquery