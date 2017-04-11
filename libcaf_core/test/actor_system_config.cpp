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

#include "caf/config.hpp"

#define CAF_SUITE actor_system_config
#include "caf/test/unit_test.hpp"

#include <sstream>
#include <iostream>

#include "caf/actor_system_config.hpp"

using namespace caf;

namespace {

// A simple dummy INI file. Note that CAF never sets the default for the thread
// pool to less than 2.
constexpr const char* case1 = R"__(
[scheduler]
max-threads=2
policy='sharing'
enable-profiling=true

; the middleman
[middleman]
app-identifier="case1"
)__";

struct fixture {
  actor_system_config cfg;
  int argc;
  std::string argv0;
  char* argv[1];

  fixture() : argc(1), argv0("./caf-test") {
    argv[0] = &argv0[0];
    // Make 100% sure we have different base values.
    cfg.scheduler_max_threads = 10u;
    cfg.scheduler_policy = atom("stealing");
    cfg.scheduler_enable_profiling = false;
  }
};

} // namespace <anonymous>

CAF_TEST_FIXTURE_SCOPE(parse_ini_tests, fixture)

CAF_TEST(simple_ini) {
  std::istringstream in{case1};
  cfg.parse(argc, argv, in);
  CAF_CHECK_EQUAL(cfg.scheduler_policy, atom("sharing"));
  CAF_CHECK_EQUAL(cfg.scheduler_max_threads, 2u);
  CAF_CHECK_EQUAL(cfg.scheduler_enable_profiling, true);
  CAF_CHECK_EQUAL(cfg.middleman_app_identifier, "case1");
}

CAF_TEST_FIXTURE_SCOPE_END()
