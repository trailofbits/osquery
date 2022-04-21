/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpfnetworkeventstable.h"

#include <osquery/logger/logger.h>

namespace osquery {

struct BPFNetworkEventsTable::PrivateData final {
  std::mutex mutex;
  tob::networkevents::INetworkEvents::EventList event_list;
};

Expected<BPFNetworkEventsTable::Ptr, BPFNetworkEventsTable::ErrorCode>
BPFNetworkEventsTable::create() {
  try {
    return Ptr(new BPFNetworkEventsTable());

  } catch (const std::bad_alloc&) {
    return createError(ErrorCode::MemoryAllocationFailure);

  } catch (const ErrorCode& error_code) {
    return createError(error_code);
  }
}

BPFNetworkEventsTable::~BPFNetworkEventsTable() {}

const std::string& BPFNetworkEventsTable::name() const {
  static const std::string kTableName{"bpf_network_events"};
  return kTableName;
}

void BPFNetworkEventsTable::addEvents(
    tob::networkevents::INetworkEvents::EventList event_list) {
  std::lock_guard<std::mutex> lock(d->mutex);

  d->event_list.reserve(d->event_list.size() + event_list.size());
  d->event_list.insert(d->event_list.end(),
                       std::make_move_iterator(event_list.begin()),
                       std::make_move_iterator(event_list.end()));
}

BPFNetworkEventsTable::BPFNetworkEventsTable() : d(new PrivateData) {}

TableColumns BPFNetworkEventsTable::columns() const {
  static const TableColumns kColumnList = {
      std::make_tuple("direction", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("pid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("tid", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("container", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("comm", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("address1", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("port1", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("address2", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("port2", TEXT_TYPE, ColumnOptions::DEFAULT),
  };

  return kColumnList;
}

TableRows BPFNetworkEventsTable::generate(QueryContext& context) {
  tob::networkevents::INetworkEvents::EventList event_list;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    event_list = std::move(d->event_list);
    d->event_list.clear();
  }

  TableRows row_list;

  for (const auto& event : event_list) {
    auto row = make_table_row();

    row["direction"] = SQL_TEXT(
        event.direction ==
                tob::networkevents::INetworkEvents::Event::Direction::Outgoing
            ? "OUT"
            : "IN");

    row["pid"] = INTEGER(event.process_id);
    row["tid"] = INTEGER(event.thread_id);

    if (event.container_id.find("docker-") == 0) {
      row["container"] = SQL_TEXT(event.container_id.c_str() + 7);
    } else {
      row["container"] = SQL_TEXT("");
    }

    row["comm"] = INTEGER(event.comm);

    if (std::holds_alternative<tob::networkevents::INetworkEvents::Event::IPv4>(
            event.source_address)) {
      const auto& source_address =
          std::get<tob::networkevents::INetworkEvents::Event::IPv4>(
              event.source_address);

      const auto& destination_address =
          std::get<tob::networkevents::INetworkEvents::Event::IPv4>(
              event.destination_address);

      row["address1"] = SQL_TEXT("127.0.0.1");
      row["address2"] = SQL_TEXT("127.0.0.1");

      row["port1"] = INTEGER(source_address.port);
      row["port2"] = INTEGER(destination_address.port);

    } else {
      const auto& source_address =
          std::get<tob::networkevents::INetworkEvents::Event::IPv6>(
              event.source_address);

      const auto& destination_address =
          std::get<tob::networkevents::INetworkEvents::Event::IPv6>(
              event.destination_address);

      row["address1"] = SQL_TEXT("::1");
      row["address2"] = SQL_TEXT("::1");

      row["port1"] = INTEGER(source_address.port);
      row["port2"] = INTEGER(destination_address.port);
    }

    row_list.push_back(std::move(row));
  }

  return row_list;
}

} // namespace osquery