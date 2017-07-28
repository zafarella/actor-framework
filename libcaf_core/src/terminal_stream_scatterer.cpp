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

#include "caf/terminal_stream_scatterer.hpp"

#include "caf/logger.hpp"

namespace caf {

terminal_stream_scatterer::~terminal_stream_scatterer() {
  // nop
}

stream_scatterer::path_ptr
terminal_stream_scatterer::add_path(const stream_id&, strong_actor_ptr,
                                   strong_actor_ptr,
                                   mailbox_element::forwarding_stack,
                                   message_id, message, stream_priority, bool) {
  CAF_LOG_ERROR("terminal_stream_scatterer::add_path called");
  return nullptr;
}

stream_scatterer::path_ptr
terminal_stream_scatterer::confirm_path(const stream_id&, const actor_addr&,
                                       strong_actor_ptr, long, bool) {
  CAF_LOG_ERROR("terminal_stream_scatterer::confirm_path called");
  return nullptr;
}

bool terminal_stream_scatterer::remove_path(const stream_id&, const actor_addr&,
                                           error, bool) {
  CAF_LOG_ERROR("terminal_stream_scatterer::remove_path called");
  return false;
}

bool terminal_stream_scatterer::paths_clean() const {
  return true;
}

void terminal_stream_scatterer::close() {
  // nop
}

void terminal_stream_scatterer::abort(error) {
  // nop
}

long terminal_stream_scatterer::num_paths() const {
  return 0;
}

bool terminal_stream_scatterer::closed() const {
  return true;
}

bool terminal_stream_scatterer::continuous() const {
  return false;
}

void terminal_stream_scatterer::continuous(bool) {
  // nop
}

stream_scatterer::path_type* terminal_stream_scatterer::path_at(size_t) {
  return nullptr;
}

void terminal_stream_scatterer::emit_batches() {
  // nop
}

stream_scatterer::path_type* terminal_stream_scatterer::find(const stream_id&,
                                                            const actor_addr&) {
  return nullptr;
}

long terminal_stream_scatterer::credit() const {
  // TODO: do something more advanced, yes?
  return 50;
}

long terminal_stream_scatterer::buffered() const {
  return 0;
}

long terminal_stream_scatterer::min_batch_size() const {
  return 0;
}

long terminal_stream_scatterer::max_batch_size() const {
  return 0;
}

long terminal_stream_scatterer::min_buffer_size() const {
  return 0;
}

duration terminal_stream_scatterer::max_batch_delay() const {
  return infinite;
}

void terminal_stream_scatterer::min_batch_size(long) {
  // nop
}

void terminal_stream_scatterer::max_batch_size(long) {
  // nop
}

void terminal_stream_scatterer::min_buffer_size(long) {
  // nop
}

void terminal_stream_scatterer::max_batch_delay(duration) {
  // nop
}

} // namespace caf
