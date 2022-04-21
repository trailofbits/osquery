/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "bpfnetworkeventstable.h"

#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

class NetworkEventsService final : public InternalRunnable {
 public:
  NetworkEventsService(BPFNetworkEventsTable& table);
  virtual ~NetworkEventsService();

 protected:
  virtual void start() override;
  virtual void stop() override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};

} // namespace osquery
