
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

#include <osquery/events/linux/containereventpublisher.h>

namespace osquery {

class ContainerEventSubscriber final
    : public EventSubscriber<ContainerEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(ContainerEventSubscriber, "event_subscriber", "container_events");


Status ContainerEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  LOG(ERROR) << "ContainerEventSubscriber::init called\n";
  subscribe(&ContainerEventSubscriber::Callback, subscription);
  return Status::success();
}

Status ContainerEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  LOG(ERROR) << "ContainerEventSubscriber::Callback called\n";
  return Status(0);
}

}
