/******************************************************************************
 *                       ____    _    _____                                   *
 *                      / ___|  / \  |  ___|    C++                           *
 *                     | |     / _ \ | |_       Actor                         *
 *                     | |___ / ___ \|  _|      Framework                     *
 *                      \____/_/   \_|_|                                      *
 *                                                                            *
 * Copyright (C) 2011 - 2017                                                  *
 * Dominik Charousset <dominik.charousset (at) haw-hamburg.de>                *
 *                                                                            *
 * Distributed under the terms and conditions of the BSD 3-Clause License or  *
 * (at your option) under the terms and conditions of the Boost Software      *
 * License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.       *
 *                                                                            *
 * If you did not receive a copy of the license files, see                    *
 * http://opensource.org/licenses/BSD-3-Clause and                            *
 * http://www.boost.org/LICENSE_1_0.txt.                                      *
 ******************************************************************************/

#ifndef CAF_LOCAL_ACTOR_HPP
#define CAF_LOCAL_ACTOR_HPP

#include <atomic>
#include <cstdint>
#include <utility>
#include <exception>
#include <functional>
#include <type_traits>
#include <forward_list>
#include <unordered_map>

#include "caf/fwd.hpp"

#include "caf/actor.hpp"
#include "caf/error.hpp"
#include "caf/extend.hpp"
#include "caf/logger.hpp"
#include "caf/message.hpp"
#include "caf/duration.hpp"
#include "caf/behavior.hpp"
#include "caf/delegated.hpp"
#include "caf/resumable.hpp"
#include "caf/actor_cast.hpp"
#include "caf/message_id.hpp"
#include "caf/exit_reason.hpp"
#include "caf/typed_actor.hpp"
#include "caf/actor_config.hpp"
#include "caf/actor_system.hpp"
#include "caf/response_type.hpp"
#include "caf/spawn_options.hpp"
#include "caf/abstract_actor.hpp"
#include "caf/abstract_group.hpp"
#include "caf/execution_unit.hpp"
#include "caf/message_handler.hpp"
#include "caf/response_promise.hpp"
#include "caf/message_priority.hpp"
#include "caf/check_typed_input.hpp"
#include "caf/monitorable_actor.hpp"
#include "caf/invoke_message_result.hpp"
#include "caf/typed_response_promise.hpp"

#include "caf/scheduler/abstract_coordinator.hpp"

#include "caf/detail/disposer.hpp"
#include "caf/detail/behavior_stack.hpp"
#include "caf/detail/typed_actor_util.hpp"
#include "caf/detail/single_reader_queue.hpp"

namespace caf {

namespace detail {

template <class... Ts>
struct make_response_promise_helper {
  using type = typed_response_promise<Ts...>;
};

template <class... Ts>
struct make_response_promise_helper<typed_response_promise<Ts...>>
    : make_response_promise_helper<Ts...> {};

template <>
struct make_response_promise_helper<response_promise> {
  using type = response_promise;
};

} // namespace detail

/// Base class for actors running on this node, either
/// living in an own thread or cooperatively scheduled.
class local_actor : public monitorable_actor {
public:

  // -- member types -----------------------------------------------------------

  /// A queue optimized for single-reader-many-writers.
  using mailbox_type = detail::single_reader_queue<mailbox_element,
                                                   detail::disposer>;

  // -- constructors, destructors, and assignment operators --------------------

  local_actor(actor_config& cfg);

  ~local_actor() override;

  void on_destroy() override;

  // -- pure virtual modifiers -------------------------------------------------

  virtual void launch(execution_unit* eu, bool lazy, bool hide) = 0;

  // -- timeout management -----------------------------------------------------

  /// Requests a new timeout for `mid`.
  /// @pre `mid.valid()`
  void request_response_timeout(const duration& d, message_id mid);

  // -- spawn functions --------------------------------------------------------

  template <class T, spawn_options Os = no_spawn_options, class... Ts>
  infer_handle_from_class_t<T> spawn(Ts&&... xs) {
    actor_config cfg{context()};
    return eval_opts(Os, system().spawn_class<T, make_unbound(Os)>(cfg, std::forward<Ts>(xs)...));
  }

  template <class T, spawn_options Os = no_spawn_options>
  infer_handle_from_state_t<T> spawn() {
    using impl = composable_behavior_based_actor<T>;
    actor_config cfg{context()};
    return eval_opts(Os, system().spawn_class<impl, make_unbound(Os)>(cfg));
  }

  template <spawn_options Os = no_spawn_options, class F, class... Ts>
  infer_handle_from_fun_t<F> spawn(F fun, Ts&&... xs) {
    actor_config cfg{context()};
    return eval_opts(Os, system().spawn_functor<make_unbound(Os)>(cfg, fun, std::forward<Ts>(xs)...));
  }

  template <class T, spawn_options Os = no_spawn_options, class Groups,
            class... Ts>
  actor spawn_in_groups(const Groups& gs, Ts&&... xs) {
    actor_config cfg{context()};
    return eval_opts(Os, system().spawn_class_in_groups<T, make_unbound(Os)>(cfg, gs.begin(), gs.end(), std::forward<Ts>(xs)...));
  }

  template <class T, spawn_options Os = no_spawn_options, class... Ts>
  actor spawn_in_groups(std::initializer_list<group> gs, Ts&&... xs) {
    actor_config cfg{context()};
    return eval_opts(Os, system().spawn_class_in_groups<T, make_unbound(Os)>(cfg, gs.begin(), gs.end(), std::forward<Ts>(xs)...));
  }

  template <class T, spawn_options Os = no_spawn_options, class... Ts>
  actor spawn_in_group(const group& grp, Ts&&... xs) {
    actor_config cfg{context()};
    auto first = &grp;
    return eval_opts(Os, system().spawn_class_in_groups<T, make_unbound(Os)>(cfg, first, first + 1, std::forward<Ts>(xs)...));
  }

  template <spawn_options Os = no_spawn_options, class Groups, class F, class... Ts>
  actor spawn_in_groups(const Groups& gs, F fun, Ts&&... xs) {
    actor_config cfg{context()};
    return eval_opts(Os, system().spawn_fun_in_groups<make_unbound(Os)>(cfg, gs.begin(), gs.end(), fun, std::forward<Ts>(xs)...));
  }

  template <spawn_options Os = no_spawn_options, class F, class... Ts>
  actor spawn_in_groups(std::initializer_list<group> gs, F fun, Ts&&... xs) {
    actor_config cfg{context()};
    return eval_opts(Os, system().spawn_fun_in_groups<make_unbound(Os)>(cfg, gs.begin(), gs.end(), fun, std::forward<Ts>(xs)...));
  }

  template <spawn_options Os = no_spawn_options, class F, class... Ts>
  actor spawn_in_group(const group& grp, F fun, Ts&&... xs) {
    actor_config cfg{context()};
    auto first = &grp;
    return eval_opts(Os, system().spawn_fun_in_groups<make_unbound(Os)>(cfg, first, first + 1, fun, std::forward<Ts>(xs)...));
  }

  // -- sending asynchronous messages ------------------------------------------

  /// Sends an exit message to `dest`.
  void send_exit(const actor_addr& whom, error reason);

  void send_exit(const strong_actor_ptr& dest, error reason);

  /// Sends an exit message to `dest`.
  template <class ActorHandle>
  void send_exit(const ActorHandle& dest, error reason) {
    dest->eq_impl(message_id::make(), ctrl(), context(),
                  exit_msg{address(), std::move(reason)});
  }

  // -- miscellaneous actor operations -----------------------------------------

  /// Returns the execution unit currently used by this actor.
  inline execution_unit* context() const {
    return context_;
  }

  /// Sets the execution unit for this actor.
  inline void context(execution_unit* x) {
    context_ = x;
  }

  /// Returns the hosting actor system.
  inline actor_system& system() const {
    CAF_ASSERT(context_);
    return context_->system();
  }

  /// @cond PRIVATE

  void monitor(abstract_actor* ptr);

  /// @endcond

  /// Returns a pointer to the sender of the current message.
  /// @pre `current_mailbox_element() != nullptr`
  inline strong_actor_ptr& current_sender() {
    CAF_ASSERT(current_element_);
    return current_element_->sender;
  }

  /// Returns the ID of the current message.
  inline message_id current_message_id() {
    CAF_ASSERT(current_element_);
    return current_element_->mid;
  }

  /// Returns the ID of the current message and marks the ID stored in the
  /// current mailbox element as answered.
  inline message_id take_current_message_id() {
    CAF_ASSERT(current_element_);
    auto result = current_element_->mid;
    current_element_->mid.mark_as_answered();
    return result;
  }

  /// Marks the current message ID as answered.
  inline void drop_current_message_id() {
    CAF_ASSERT(current_element_);
    current_element_->mid.mark_as_answered();
  }

  /// Returns a pointer to the next stage from the forwarding path of the
  /// current message or `nullptr` if the path is empty.
  inline strong_actor_ptr current_next_stage() {
    CAF_ASSERT(current_element_);
    auto& stages = current_element_->stages;
    if (!stages.empty())
      stages.back();
    return nullptr;
  }

  /// Returns a pointer to the next stage from the forwarding path of the
  /// current message and removes it from the path. Returns `nullptr` if the
  /// path is empty.
  inline strong_actor_ptr take_current_next_stage() {
    CAF_ASSERT(current_element_);
    auto& stages = current_element_->stages;
    if (!stages.empty()) {
      auto result = stages.back();
      stages.pop_back();
      return result;
    }
    return nullptr;
  }

  /// Returns the forwarding stack from the current mailbox element.
  const mailbox_element::forwarding_stack& current_forwarding_stack() {
    CAF_ASSERT(current_element_);
    return current_element_->stages;
  }

  /// Moves the forwarding stack from the current mailbox element.
  mailbox_element::forwarding_stack take_current_forwarding_stack() {
    CAF_ASSERT(current_element_);
    return std::move(current_element_->stages);
  }

  /// Returns a pointer to the currently processed mailbox element.
  inline mailbox_element* current_mailbox_element() {
    return current_element_;
  }

  /// Adds a unidirectional `monitor` to `whom`.
  /// @note Each call to `monitor` creates a new, independent monitor.
  template <class Handle>
  void monitor(const Handle& whom) {
    monitor(actor_cast<abstract_actor*>(whom));
  }

  /// Removes a monitor from `whom`.
  void demonitor(const actor_addr& whom);

  /// Removes a monitor from `whom`.
  inline void demonitor(const actor& whom) {
    demonitor(whom.address());
  }

  /// Can be overridden to perform cleanup code after an actor
  /// finished execution.
  virtual void on_exit();

  /// Creates a `typed_response_promise` to respond to a request later on.
  /// `make_response_promise<typed_response_promise<int, int>>()`
  /// is equivalent to `make_response_promise<int, int>()`.
  template <class... Ts>
  typename detail::make_response_promise_helper<Ts...>::type
  make_response_promise() {
    auto& ptr = current_element_;
    if (!ptr)
      return {};
    auto& mid = ptr->mid;
    if (mid.is_answered())
      return {};
    return {this->ctrl(), *ptr};
  }

  /// Creates a `response_promise` to respond to a request later on.
  inline response_promise make_response_promise() {
    return make_response_promise<response_promise>();
  }

  /// Creates a `typed_response_promise` and responds immediately.
  /// Return type is deduced from arguments.
  /// Return value is implicitly convertible to untyped response promise.
  template <class... Ts,
            class R =
              typename detail::make_response_promise_helper<
                typename std::decay<Ts>::type...
              >::type>
  R response(Ts&&... xs) {
    auto promise = make_response_promise<R>();
    promise.deliver(std::forward<Ts>(xs)...);
    return promise;
  }

  const char* name() const override;

  /// Serializes the state of this actor to `sink`. This function is
  /// only called if this actor has set the `is_serializable` flag.
  /// The default implementation throws a `std::logic_error`.
  virtual error save_state(serializer& sink, unsigned int version);

  /// Deserializes the state of this actor from `source`. This function is
  /// only called if this actor has set the `is_serializable` flag.
  /// The default implementation throws a `std::logic_error`.
  virtual error load_state(deserializer& source, unsigned int version);

  /// Returns the currently defined fail state. If this reason is not
  /// `none` then the actor will terminate with this error after executing
  /// the current message handler.
  inline const error& fail_state() const {
    return fail_state_;
  }

  // -- here be dragons: end of public interface -------------------------------

  /// @cond PRIVATE

  template <class ActorHandle>
  inline ActorHandle eval_opts(spawn_options opts, ActorHandle res) {
    if (has_monitor_flag(opts))
      monitor(res->address());
    if (has_link_flag(opts))
      link_to(res->address());
    return res;
  }

  // returns 0 if last_dequeued() is an asynchronous or sync request message,
  // a response id generated from the request id otherwise
  inline message_id get_response_id() const {
    auto mid = current_element_->mid;
    return (mid.is_request()) ? mid.response_id() : message_id();
  }

  template <message_priority P = message_priority::normal,
            class Handle = actor, class... Ts>
  typename response_type<
    typename Handle::signatures,
    detail::implicit_conversions_t<typename std::decay<Ts>::type>...
  >::delegated_type
  delegate(const Handle& dest, Ts&&... xs) {
    static_assert(sizeof...(Ts) > 0, "nothing to delegate");
    using token =
      detail::type_list<
        typename detail::implicit_conversions<
          typename std::decay<Ts>::type
        >::type...>;
    static_assert(response_type_unbox<signatures_of_t<Handle>, token>::valid,
                  "receiver does not accept given message");
    auto mid = current_element_->mid;
    current_element_->mid = P == message_priority::high
                            ? mid.with_high_priority()
                            : mid.with_normal_priority();
    dest->enqueue(make_mailbox_element(std::move(current_element_->sender),
                                       mid, std::move(current_element_->stages),
                                       std::forward<Ts>(xs)...),
                  context());
    return {};
  }

  inline mailbox_type& mailbox() {
    return mailbox_;
  }

  virtual void initialize();

  bool cleanup(error&& fail_state, execution_unit* host) override;

  message_id new_request_id(message_priority mp);

  // -- message processing -----------------------------------------------------

  /// Returns the next message from the mailbox or `nullptr`
  /// if the mailbox is drained.
  mailbox_element_ptr next_message();

  /// Returns whether the mailbox contains at least one element.
  bool has_next_message();

  /// Appends `x` to the cache for later consumption.
  void push_to_cache(mailbox_element_ptr ptr);

protected:
  // -- member variables -------------------------------------------------------

  // used by both event-based and blocking actors
  mailbox_type mailbox_;

  // identifies the execution unit this actor is currently executed by
  execution_unit* context_;

  // pointer to the sender of the currently processed message
  mailbox_element* current_element_;

  // last used request ID
  message_id last_request_id_;

  /// Factory function for returning initial behavior in function-based actors.
  std::function<behavior (local_actor*)> initial_behavior_fac_;
};

} // namespace caf

#endif // CAF_LOCAL_ACTOR_HPP
