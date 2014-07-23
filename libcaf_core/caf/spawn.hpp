/******************************************************************************
 *                       ____    _    _____                                   *
 *                      / ___|  / \  |  ___|    C++                           *
 *                     | |     / _ \ | |_       Actor                         *
 *                     | |___ / ___ \|  _|      Framework                     *
 *                      \____/_/   \_|_|                                      *
 *                                                                            *
 * Copyright (C) 2011 - 2014                                                  *
 * Dominik Charousset <dominik.charousset (at) haw-hamburg.de>                *
 *                                                                            *
 * Distributed under the terms and conditions of the BSD 3-Clause License or  *
 * (at your option) under the terms and conditions of the Boost Software      *
 * License 1.0. See accompanying files LICENSE and LICENCE_ALTERNATIVE.       *
 *                                                                            *
 * If you did not receive a copy of the license files, see                    *
 * http://opensource.org/licenses/BSD-3-Clause and                            *
 * http://www.boost.org/LICENSE_1_0.txt.                                      *
 ******************************************************************************/

#ifndef CAF_SPAWN_HPP
#define CAF_SPAWN_HPP

#include <type_traits>

#include "caf/scheduler.hpp"
#include "caf/spawn_fwd.hpp"
#include "caf/typed_actor.hpp"
#include "caf/spawn_options.hpp"
#include "caf/typed_event_based_actor.hpp"

#include "caf/policy/no_resume.hpp"
#include "caf/policy/prioritizing.hpp"
#include "caf/policy/no_scheduling.hpp"
#include "caf/policy/actor_policies.hpp"
#include "caf/policy/nestable_invoke.hpp"
#include "caf/policy/not_prioritizing.hpp"
#include "caf/policy/sequential_invoke.hpp"
#include "caf/policy/event_based_resume.hpp"
#include "caf/policy/cooperative_scheduling.hpp"

#include "caf/detail/logging.hpp"
#include "caf/detail/type_traits.hpp"
#include "caf/detail/make_counted.hpp"
#include "caf/detail/proper_actor.hpp"
#include "caf/detail/typed_actor_util.hpp"
#include "caf/detail/implicit_conversions.hpp"

namespace caf {

class execution_unit;

// marker interface to prevent spawn_impl to wrap
// the implementation in a proper_actor
class spawn_as_is {};

template <class C, spawn_options Os, typename BeforeLaunch, class... Ts>
intrusive_ptr<C> spawn_impl(execution_unit* eu, BeforeLaunch before_launch_fun,
              Ts&&... args) {
  static_assert(   !std::is_base_of<blocking_actor, C>::value
          || has_blocking_api_flag(Os),
          "C is derived type of blocking_actor but "
          "blocking_api_flag is missing");
  static_assert(is_unbound(Os),
          "top-level spawns cannot have monitor or link flag");
  CAF_LOGF_TRACE("spawn " << detail::demangle<C>());
  using scheduling_policy =
    typename std::conditional<
      has_detach_flag(Os) || has_blocking_api_flag(Os),
      policy::no_scheduling,
      policy::cooperative_scheduling
    >::type;
  using priority_policy =
    typename std::conditional<
      has_priority_aware_flag(Os),
      policy::prioritizing,
      policy::not_prioritizing
    >::type;
  using resume_policy =
    typename std::conditional<
      has_blocking_api_flag(Os),
      policy::no_resume,
      policy::event_based_resume
    >::type;
  using invoke_policy =
    typename std::conditional<
      has_blocking_api_flag(Os),
      policy::nestable_invoke,
      policy::sequential_invoke
    >::type;
  using policy_token =
    policy::actor_policies<
      scheduling_policy,
      priority_policy,
      resume_policy,
      invoke_policy
    >;
  using actor_impl =
    typename std::conditional<
      std::is_base_of<spawn_as_is, C>::value,
      C,
      detail::proper_actor<C, policy_token>
    >::type;
  auto ptr = detail::make_counted<actor_impl>(std::forward<Ts>(args)...);
  CAF_LOGF_DEBUG("spawned actor with ID " << ptr->id());
  CAF_PUSH_AID(ptr->id());
  before_launch_fun(ptr.get());
  ptr->launch(has_hide_flag(Os), eu);
  return ptr;
}

template <class T>
struct spawn_fwd {
  static inline T& fwd(T& arg) { return arg; }
  static inline const T& fwd(const T& arg) { return arg; }
  static inline T&& fwd(T&& arg) { return std::move(arg); }

};

template <class T, class... Ts>
struct spawn_fwd<T(Ts...)> {
  using fun_pointer = T (*)(Ts...);
  static inline fun_pointer fwd(fun_pointer arg) { return arg; }

};

template <>
struct spawn_fwd<scoped_actor> {
  template <class T>
  static inline actor fwd(T& arg) {
    return arg;
  }
};

// forwards the arguments to spawn_impl, replacing pointers
// to actors with instances of 'actor'
template <class C, spawn_options Os, typename BeforeLaunch, class... Ts>
intrusive_ptr<C> spawn_class(execution_unit* eu, BeforeLaunch before_launch_fun,
               Ts&&... args) {
  return spawn_impl<C, Os>(
    eu, before_launch_fun,
    spawn_fwd<typename detail::rm_const_and_ref<Ts>::type>::fwd(
      std::forward<Ts>(args))...);
}

template <spawn_options Os, typename BeforeLaunch, typename F, class... Ts>
actor spawn_functor(execution_unit* eu, BeforeLaunch cb, F fun, Ts&&... args) {
  using trait = typename detail::get_callable_trait<F>::type;
  using arg_types = typename trait::arg_types;
  using first_arg = typename detail::tl_head<arg_types>::type;
  using base_class =
    typename std::conditional<
      std::is_pointer<first_arg>::value,
      typename std::remove_pointer<first_arg>::type,
      typename std::conditional<
        has_blocking_api_flag(Os),
        blocking_actor,
        event_based_actor
      >::type
    >::type;
  constexpr bool has_blocking_base =
    std::is_base_of<blocking_actor, base_class>::value;
  static_assert(has_blocking_base || !has_blocking_api_flag(Os),
          "blocking functor-based actors "
          "need to be spawned using the blocking_api flag");
  static_assert(!has_blocking_base || has_blocking_api_flag(Os),
          "non-blocking functor-based actors "
          "cannot be spawned using the blocking_api flag");
  using impl_class = typename base_class::functor_based;
  return spawn_class<impl_class, Os>(eu, cb, fun, std::forward<Ts>(args)...);
}

/**
 * @ingroup ActorCreation
 * @{
 */

/**
 * @brief Spawns an actor of type @p C.
 * @param args Constructor arguments.
 * @tparam Impl Subtype of {@link event_based_actor} or {@link sb_actor}.
 * @tparam Os Optional flags to modify <tt>spawn</tt>'s behavior.
 * @returns An {@link actor} to the spawned {@link actor}.
 */
template <class Impl, spawn_options Os = no_spawn_options, class... Ts>
actor spawn(Ts&&... args) {
  return spawn_class<Impl, Os>(nullptr, empty_before_launch_callback{},
                 std::forward<Ts>(args)...);
}

/**
 * @brief Spawns a new {@link actor} that evaluates given arguments.
 * @param args A functor followed by its arguments.
 * @tparam Os Optional flags to modify <tt>spawn</tt>'s behavior.
 * @returns An {@link actor} to the spawned {@link actor}.
 */
template <spawn_options Os = no_spawn_options, class... Ts>
actor spawn(Ts&&... args) {
  static_assert(sizeof...(Ts) > 0, "too few arguments provided");
  return spawn_functor<Os>(nullptr, empty_before_launch_callback{},
               std::forward<Ts>(args)...);
}

/**
 * @brief Spawns an actor of type @p C that immediately joins @p grp.
 * @param args Constructor arguments.
 * @tparam Impl Subtype of {@link event_based_actor} or {@link sb_actor}.
 * @tparam Os Optional flags to modify <tt>spawn</tt>'s behavior.
 * @returns An {@link actor} to the spawned {@link actor}.
 * @note The spawned has joined the group before this function returns.
 */
template <class Impl, spawn_options Os = no_spawn_options, class... Ts>
actor spawn_in_group(const group& grp, Ts&&... args) {
  return spawn_class<Impl, Os>(nullptr, group_subscriber{grp},
                 std::forward<Ts>(args)...);
}

/**
 * @brief Spawns a new actor that evaluates given arguments and
 *    immediately joins @p grp.
 * @param args A functor followed by its arguments.
 * @tparam Os Optional flags to modify <tt>spawn</tt>'s behavior.
 * @returns An {@link actor} to the spawned {@link actor}.
 * @note The spawned has joined the group before this function returns.
 */
template <spawn_options Os = no_spawn_options, class... Ts>
actor spawn_in_group(const group& grp, Ts&&... args) {
  static_assert(sizeof...(Ts) > 0, "too few arguments provided");
  return spawn_functor<Os>(nullptr, group_subscriber{grp},
               std::forward<Ts>(args)...);
}

namespace detail {

template <class... Rs>
class functor_based_typed_actor : public typed_event_based_actor<Rs...> {

  using super = typed_event_based_actor<Rs...>;

 public:

  using pointer = typed_event_based_actor<Rs...>*;
  using behavior_type = typename super::behavior_type;

  using no_arg_fun = std::function<behavior_type()>;
  using one_arg_fun1 = std::function<behavior_type(pointer)>;
  using one_arg_fun2 = std::function<void(pointer)>;

  template <class F, class... Ts>
  functor_based_typed_actor(F fun, Ts&&... args) {
    using trait = typename detail::get_callable_trait<F>::type;
    using arg_types = typename trait::arg_types;
    using result_type = typename trait::result_type;
    constexpr bool returns_behavior =
      std::is_same<result_type, behavior_type>::value;
    constexpr bool uses_first_arg = std::is_same<
      typename detail::tl_head<arg_types>::type, pointer>::value;
    std::integral_constant<bool, returns_behavior> token1;
    std::integral_constant<bool, uses_first_arg> token2;
    set(token1, token2, std::move(fun), std::forward<Ts>(args)...);
  }

 protected:

  behavior_type make_behavior() override { return m_fun(this); }

 private:

  template <class F>
  void set(std::true_type, std::true_type, F&& fun) {
    // behavior_type (pointer)
    m_fun = std::forward<F>(fun);
  }

  template <class F>
  void set(std::false_type, std::true_type, F fun) {
    // void (pointer)
    m_fun = [fun](pointer ptr) {
      fun(ptr);
      return behavior_type{};

    };
  }

  template <class F>
  void set(std::true_type, std::false_type, F fun) {
    // behavior_type ()
    m_fun = [fun](pointer) { return fun(); };
  }

  // (false_type, false_type) is an invalid functor for typed actors

  template <class Token, typename F, typename T0, class... Ts>
  void set(Token t1, std::true_type t2, F fun, T0&& arg0, Ts&&... args) {
    set(t1, t2,
      std::bind(fun, std::placeholders::_1, std::forward<T0>(arg0),
            std::forward<Ts>(args)...));
  }

  template <class Token, typename F, typename T0, class... Ts>
  void set(Token t1, std::false_type t2, F fun, T0&& arg0, Ts&&... args) {
    set(t1, t2,
      std::bind(fun, std::forward<T0>(arg0), std::forward<Ts>(args)...));
  }

  one_arg_fun1 m_fun;

};

template <class TypedBehavior, class FirstArg>
struct infer_typed_actor_base;

template <class... Rs, class FirstArg>
struct infer_typed_actor_base<typed_behavior<Rs...>, FirstArg> {
  using type = functor_based_typed_actor<Rs...>;

};

template <class... Rs>
struct infer_typed_actor_base<void, typed_event_based_actor<Rs...>*> {
  using type = functor_based_typed_actor<Rs...>;

};

} // namespace detail

/**
 * @brief Spawns a typed actor of type @p C.
 * @param args Constructor arguments.
 * @tparam C Subtype of {@link typed_event_based_actor}.
 * @tparam Os Optional flags to modify <tt>spawn</tt>'s behavior.
 * @returns A {@link typed_actor} handle to the spawned actor.
 */
template <class C, spawn_options Os = no_spawn_options, class... Ts>
typename detail::actor_handle_from_signature_list<typename C::signatures>::type
spawn_typed(Ts&&... args) {
  return spawn_class<C, Os>(nullptr, empty_before_launch_callback{},
                std::forward<Ts>(args)...);
}

template <spawn_options Os, typename BeforeLaunch, typename F, class... Ts>
typename detail::infer_typed_actor_handle<
  typename detail::get_callable_trait<F>::result_type,
  typename detail::tl_head<
    typename detail::get_callable_trait<F>::arg_types>::type>::type
spawn_typed_functor(execution_unit* eu, BeforeLaunch bl, F fun, Ts&&... args) {
  using impl =
    typename detail::infer_typed_actor_base<
      typename detail::get_callable_trait<F>::result_type,
      typename detail::tl_head<
        typename detail::get_callable_trait<F>::arg_types
      >::type
    >::type;
  return spawn_class<impl, Os>(eu, bl, fun, std::forward<Ts>(args)...);
}

/**
 * @brief Spawns a typed actor from a functor.
 * @param args A functor followed by its arguments.
 * @tparam Os Optional flags to modify <tt>spawn</tt>'s behavior.
 * @returns An {@link actor} to the spawned {@link actor}.
 */
template <spawn_options Os = no_spawn_options, typename F, class... Ts>
typename detail::infer_typed_actor_handle<
  typename detail::get_callable_trait<F>::result_type,
  typename detail::tl_head<
    typename detail::get_callable_trait<F>::arg_types>::type>::type
spawn_typed(F fun, Ts&&... args) {
  return spawn_typed_functor<Os>(nullptr, empty_before_launch_callback{},
                   std::move(fun), std::forward<Ts>(args)...);
}

/** @} */

} // namespace caf

#endif // CAF_SPAWN_HPP