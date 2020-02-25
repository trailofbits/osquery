/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "lxdeventpublisher.h"

#include <unordered_map>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/status/status.h>

#include <boost/asio.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/websocket/stream.hpp>

#if !defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
#error Boost error: Local sockets not available
#endif

namespace osquery {

FLAG(string,
     lxd_events_socket,
     "/var/lib/lxd/unix.socket",
     "LXD UNIX domain socket path");

FLAG(string,
     lxd_event_types,
     "",
     "Comma separated LXD event types we want to receive")

FLAG(bool, enable_lxd_events_publisher, false, "Enable LXD events publisher");

bool IsPublisherEnabled() {
  return FLAGS_enable_lxd_events_publisher;
}

REGISTER(LXDEventPublisher, "event_publisher", "lxdevent");

namespace {
enum class JSONFieldType { String, Object, Bool, Number };

Status verifyFieldPresenceAndType(
    const std::string& event_name,
    const rapidjson::Value& doc,
    const std::unordered_map<std::string, JSONFieldType>&
        json_field_constraints) {
  for (const auto& constraint_pair : json_field_constraints) {
    if (!doc.HasMember(constraint_pair.first)) {
      return Status::failure(event_name + " event has no " +
                             constraint_pair.first + " field");
    }

    bool valid = false;
    std::string type;
    switch (constraint_pair.second) {
    case JSONFieldType::String: {
      valid = doc[constraint_pair.first].IsString();
      type = "a string";
      break;
    }
    case JSONFieldType::Object: {
      valid = doc[constraint_pair.first].IsObject();
      type = "an object";
      break;
    }
    case JSONFieldType::Bool: {
      valid = doc[constraint_pair.first].IsBool();
      type = "a bool";
      break;
    }
    case JSONFieldType::Number: {
      valid = doc[constraint_pair.first].IsNumber();
      type = "a number";
      break;
    }
    default:
      return Status::failure(
          "Unsupported field type " +
          std::to_string(static_cast<int>(constraint_pair.second)));
    }

    if (!valid) {
      return Status::failure(event_name + " event " + constraint_pair.first +
                             " field is not " + type);
    }
  }

  return Status::success();
}
} // namespace

Status LXDEventPublisher::setUp() {
  if (!IsPublisherEnabled()) {
    return Status::failure("Publisher disabled via configuration");
  }

  return Status::success();
}

Status LXDEventPublisher::readEvents() {
  try {
    while (!interrupt_) {
      websocket_stream_->async_read(
          read_buffer_,
          [&](const boost::system::error_code& ec,
              const std::size_t& transferred) {
            if (ec == boost::system::errc::success) {
              std::unique_lock<std::mutex> lock(publisher_mutex_);
              events_.emplace_back(
                  boost::beast::buffers_to_string(read_buffer_.data()));
              read_buffer_.consume(transferred);
            } else {
              interrupt_ = true;
              ec_ = ec;
            }
          });

      int handler_run = 0;
      while (!interrupt_ && handler_run == 0) {
        handler_run = io_context_.poll();
        io_context_.restart();

        if (!interrupt_ && handler_run == 0) {
          std::this_thread::sleep_for(std::chrono::seconds(1));
        }
      }
    }
  } catch (std::exception& ex) {
    return Status::failure(ex.what());
  }

  if (ec_ != boost::system::errc::success) {
    return Status::failure(ec_.message());
  }

  return Status::success();
}

void LXDEventPublisher::cleanup() {
  interrupt_ = true;
  running_ = false;
  event_reader_status_.get();
  interrupt_ = false;
  boost::system::error_code ec;
  websocket_stream_->next_layer().cancel(ec);
  io_context_.stop();
  websocket_stream_->next_layer().shutdown(
      local::stream_protocol::socket::shutdown_both);
  websocket_stream_->next_layer().close();
  websocket_stream_.reset();
}

void LXDEventPublisher::configure() {
  if (!IsPublisherEnabled()) {
    return;
  }

  try {
    if (running_) {
      cleanup();
    }

    local::stream_protocol::endpoint ep(FLAGS_lxd_events_socket);
    websocket_stream_ =
        std::make_unique<websocket::stream<local::stream_protocol::socket>>(
            io_context_);
    websocket_stream_->next_layer().connect(ep);
    boost::asio::socket_base::keep_alive option(true);
    websocket_stream_->next_layer().set_option(option);
    std::string event_url = "/1.0/events";

    if (!FLAGS_lxd_event_types.empty()) {
      event_url += "?type=" + FLAGS_lxd_event_types;
    }

    websocket_stream_->async_handshake(
        "localhost", event_url, [&](boost::system::error_code const& ec) {
          if (ec != boost::system::errc::success) {
            ec_ = ec;
            interrupt_ = true;
            running_ = false;
          }
        });

    io_context_.run();
    io_context_.restart();

    if (!websocket_stream_->is_open()) {
      LOG(INFO) << "Failed to open the websocket";
      return;
    }

    event_reader_status_ = std::async([&]() -> Status { return readEvents(); });
    running_ = true;
  } catch (std::exception& ex) {
    LOG(INFO) << "Error calling LXD API: " << ex.what();
    return;
  }
}

void LXDEventPublisher::tearDown() {
  if (!IsPublisherEnabled()) {
    return;
  }

  if (running_) {
    cleanup();
  }
}

Status LXDEventPublisher::parseEvent(const std::string& event,
                                     rapidjson::Document& rapidjson_doc) {
  {
    JSON document;
    auto status = document.fromString(event);

    if (!status.ok()) {
      return status;
    }

    rapidjson_doc = std::move(document.doc());
  }

  if (!rapidjson_doc.IsObject()) {
    return Status::failure("Parsed event is not a JSON object");
  }

  auto status =
      verifyFieldPresenceAndType("Parsed",
                                 rapidjson_doc,
                                 {{"type", JSONFieldType::String},
                                  {"timestamp", JSONFieldType::String},
                                  {"metadata", JSONFieldType::Object}});
  if (!status.ok()) {
    return status;
  }

  std::string s;
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  rapidjson_doc.Accept(writer);
  s = sb.GetString();

  return Status::success();
}

bool LXDEventPublisher::shouldFire(const LXDSubscriptionContextRef& sc,
                                   const LXDEventContextRef& ec) const {
  if (ec->lxd_event == nullptr) {
    return false;
  }

  return sc->event_type_subscription_ == ec->lxd_event->type_;
}

Status LXDEventPublisher::run() {
  if (!IsPublisherEnabled()) {
    return Status::failure("Publisher disabled via configuration");
  }

  std::unique_lock<std::mutex> lock(publisher_mutex_);
  for (const auto& event_message : events_) {
    auto event_context = createEventContext();

    rapidjson::Document doc;
    auto status = parseEvent(event_message, doc);

    if (!status.ok()) {
      LOG(INFO) << "Failed to parse an event message: " << status.getMessage();
      VLOG(1) << event_message;
      continue;
    }

    bool has_location = false;
    if (doc.HasMember("location")) {
      has_location = true;
      if (!doc.IsString()) {
        LOG(INFO) << "Event has a location field but it's not a string";
        continue;
      }
    }

    auto type = std::string(doc["type"].GetString());
    const auto& metadata = doc["metadata"];

    if (type == "logging") {
      auto status =
          verifyFieldPresenceAndType("Logging",
                                     metadata,
                                     {{"level", JSONFieldType::String},
                                      {"message", JSONFieldType::String},
                                      {"context", JSONFieldType::Object}});

      if (!status.ok()) {
        LOG(INFO) << "Failed to parse the Logging event: "
                  << status.getMessage();
        VLOG(1) << event_message;
        continue;
      }

      const auto& context = metadata["context"];

      rapidjson::StringBuffer context_sb;
      rapidjson::Writer<rapidjson::StringBuffer> writer(context_sb);
      context.Accept(writer);
      std::string context_string = context_sb.GetString();
      if (context_string == "null") {
        context_string.clear();
      }

      std::string location = has_location ? doc["location"].GetString() : "";
      event_context->lxd_event =
          std::make_unique<LXDLoggingEvent>(doc["timestamp"].GetString(),
                                            location,
                                            metadata["level"].GetString(),
                                            metadata["message"].GetString(),
                                            context_string);

    } else if (type == "operation") {
      auto status =
          verifyFieldPresenceAndType("Logging",
                                     metadata,
                                     {{"id", JSONFieldType::String},
                                      {"class", JSONFieldType::String},
                                      {"created_at", JSONFieldType::String},
                                      {"updated_at", JSONFieldType::String},
                                      {"status", JSONFieldType::String},
                                      {"status_code", JSONFieldType::Number},
                                      {"resources", JSONFieldType::Object},
                                      {"metadata", JSONFieldType::Object},
                                      {"may_cancel", JSONFieldType::Bool},
                                      {"err", JSONFieldType::String}});

      if (!status.ok()) {
        LOG(INFO) << "Failed to parse the Operation event: "
                  << status.getMessage();
        VLOG(1) << event_message;
        continue;
      }

      const auto& resources = metadata["resources"];
      const auto& operation_metadata = metadata["metadata"];

      rapidjson::StringBuffer resources_sb;
      rapidjson::Writer<rapidjson::StringBuffer> writer(resources_sb);
      resources.Accept(writer);
      std::string resources_string = resources_sb.GetString();

      if (resources_string == "null") {
        resources_string.clear();
      }

      writer.Reset(resources_sb);

      operation_metadata.Accept(writer);
      std::string operation_metadata_string = resources_sb.GetString();

      if (operation_metadata_string == "null") {
        operation_metadata_string.clear();
      }

      std::string location = has_location ? doc["location"].GetString() : "";
      event_context->lxd_event = std::make_unique<LXDOperationEvent>(
          doc["timestamp"].GetString(),
          location,
          metadata["id"].GetString(),
          metadata["class"].GetString(),
          metadata["created_at"].GetString(),
          metadata["updated_at"].GetString(),
          metadata["status"].GetString(),
          metadata["status_code"].GetInt(),
          resources_string,
          operation_metadata_string,
          metadata["may_cancel"].GetBool(),
          metadata["err"].GetString());
    } else if (type == "lifecycle") {
      auto status =
          verifyFieldPresenceAndType("Lifecycle",
                                     metadata,
                                     {{"action", JSONFieldType::String},
                                      {"source", JSONFieldType::String}});

      if (!status.ok()) {
        LOG(INFO) << "Failed to parse the Lifecycle event: "
                  << status.getMessage();
        VLOG(1) << event_message;
        continue;
      }

      std::string context_string;
      if (metadata.HasMember("context")) {
        const auto& context = metadata["context"];

        rapidjson::StringBuffer context_sb;
        rapidjson::Writer<rapidjson::StringBuffer> writer(context_sb);
        context.Accept(writer);
        context_string = context_sb.GetString();

        if (context_string == "null") {
          context_string.clear();
        }
      }

      std::string location = has_location ? doc["location"].GetString() : "";
      event_context->lxd_event =
          std::make_unique<LXDLifecycleEvent>(doc["timestamp"].GetString(),
                                              location,
                                              metadata["action"].GetString(),
                                              metadata["source"].GetString(),
                                              context_string);
    } else {
      LOG(INFO) << "Parsed an unknown event type: " << type;
      VLOG(1) << "Unknown event: " << event_message;
      continue;
    }

    fire(event_context);
  }

  events_.clear();

  return Status::success();
}
} // namespace osquery