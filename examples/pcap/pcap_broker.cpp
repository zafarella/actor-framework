/******************************************************************************
 * This example illustrates how to integrate third-party networking           *
 * into CAF's I/O loop. Note: this examples does *only* work with the         *
 * default multiplexer.                                                       *
 ******************************************************************************/

#include <pcap.h>

#include "caf/all.hpp"
#include "caf/io/all.hpp"

// not included by the convenience header
// since usually transparent to CAF users
#include "caf/io/network/default_multiplexer.hpp"

struct pcap_event {
  pcap_t* ptr;
};

// We never use this message type for remote communication.
CAF_ALLOW_UNSAFE_MESSAGE_TYPE(pcap_event)

namespace {

using namespace caf;
using namespace caf::io;
using namespace caf::io::network;

class pcap_handler : public event_handler {
public:
  pcap_handler(default_multiplexer& ref, pcap_t* ptr, broker* selfptr)
      : event_handler(ref, pcap_get_selectable_fd(ptr)),
        ptr_(ptr),
        self_(selfptr),
        strong_self_(actor_cast<strong_actor_ptr>(selfptr)) {
    // Add this object to the I/O loop.
    ref.add(operation::read, fd(), this);
  }

  ~pcap_handler() {
    pcap_close(ptr_);
  }

  void handle_event(operation op) override {
    switch (op) {
      case operation::read: {
        // Read event on file handle. Only proceed if the broker did not signal
        // a shutdown by setting self_ to nullptr.
        if (self_) {
          // Create a message on the stack and call our broker with it.
          mailbox_element_vals<pcap_event> val{nullptr, message_id::make(),
                                               {}, pcap_event{ptr_}};
          self_->activate(&backend(), val);
        }
        break;
      }
      case operation::write:
        // write event on file handle, should never happen for PCAP
        std::cerr << "Write event on PCAP socket." << std::endl;
        std::terminate();
        break;
      case operation::propagate_error:
        std::cerr << "Error on PCAP socket." << std::endl;
        std::terminate();
        break;
    }
  }

  void removed_from_loop(operation op) override {
    switch (op) {
      case operation::read:
        // Removed from loop for read events. It's safe to delete this now.
        delete this;
        break;
      case operation::write:
        // Removed from loop for write events.
        std::cerr << "Removed from I/O for write events, should never happen"
                  << std::endl;
        std::terminate();
        break;
      case operation::propagate_error:
        std::cerr << "Removed from I/O due to socket error, should never happen"
                  << std::endl;
        std::terminate();
        break;
    }
  }

  void shutdown() {
    // Deregister event handler from multiplexer. This will cause the event
    // handler to delete itself.
    backend().del(operation::read, fd(), this);
    // Also "unregister" this broker at the handler to make sure no dangling
    // pointer action is happening.
    self_ = nullptr;
    // Note: we do *not* reset the strong pointer yet. This is done by the
    // destructor once the multiplexer removes this handler from the I/O loop.
  }

private:
  // Our PCAP handle.
  pcap_t* ptr_;
  // Raw pointer to the parent actor.
  broker* self_;
  // Owning pointer to our parent to keep it alive as long any PCAP is going on.
  strong_actor_ptr strong_self_;
};

// Keeps state for the pcap broker.
struct pcap_broker_state {
  // Set in the initialization code of pcap_broker.
  pcap_handler* ptr;

  // Used to collect active sources before running code once per I/O loop
  // iteration. In this example we only have a single source. This serves as an
  // example how to multiplex using the io_cycle_atom API.
  std::vector<pcap_event> events;

  // Tells the PCAP handler that it's "parent" actor is shutting down.
  ~pcap_broker_state() {
    ptr->shutdown();
  }
};

behavior pcap_broker(stateful_actor<pcap_broker_state, broker>* self) {
  char errbuf[PCAP_ERRBUF_SIZE];
  // Grab a device.
  auto dev = pcap_lookupdev(errbuf);
  if (dev == nullptr) {
    std::cerr << "Couldn't find default device: " << errbuf << std::endl;
    return {};
  }
  // Find the properties for the device.
  bpf_u_int32 net;
  bpf_u_int32 mask;
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    std::cerr << "Couldn't get netmask for device " << dev << ": " << errbuf
              << std::endl;
    return {};
  }
  // Open the session in promiscuous mode.
  auto handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
    return {};
  }
  // Compile and apply some filter.
  bpf_program fp;
  char filter_exp[] = "";
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    std::cerr << "Couldn't parse filter " << filter_exp << ": "
              << pcap_geterr(handle) << std::endl;
    return {};
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    std::cerr << "Couldn't install filter " << filter_exp << ": "
              << pcap_geterr(handle) << std::endl;
    return {};
  }
  // Hook PCAP source into CAF's I/O loop.
  auto& mpx = dynamic_cast<default_multiplexer&>(self->backend());
  self->state.ptr = new pcap_handler(mpx, handle, self);
  // Tell I/O loop we want to receive a message whenever a cycle ends.
  mpx.add_cycle_listener(self);
  // Return the behavior for this broker and quit after 3s.
  self->delayed_send(self, std::chrono::seconds(3), close_atom::value);
  return {
    [=](pcap_event x) {
      self->state.events.emplace_back(x);
    },
    [=](io_cycle_atom) {
      auto& events = self->state.events;
      if (!events.empty()) {
        std::cout << "Got " << events.size() << " events this cycle."
                  << std::endl;
        for (auto& event : events) {
          pcap_pkthdr header;
          auto packet = pcap_next(event.ptr, &header);
          CAF_IGNORE_UNUSED(packet);
          std::cout << "Jacked a packet with length of "
                    << header.len << std::endl;
        }
        events.clear();
      }
    },
    [=](close_atom) {
      std::cout << "3s of recording are enough. :)" << std::endl;
      self->quit();
    }
  };
}

void caf_main(actor_system& sys) {
  sys.middleman().spawn_broker(pcap_broker);
}

} // namespace

CAF_MAIN(io::middleman)
