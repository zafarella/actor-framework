#include <thread>
#include <string>
#include <cstring>
#include <sstream>
#include <iostream>
#include <functional>

#include "test.hpp"
#include "ping_pong.hpp"
#include "cppa/cppa.hpp"
#include "cppa/logging.hpp"
#include "cppa/exception.hpp"

using namespace std;
using namespace cppa;

namespace {

typedef std::pair<std::string, std::string> string_pair;

typedef vector<actor> actor_vector;

void reflector(untyped_actor* self) {
    self->become (
        others() >> [=] {
            CPPA_LOGF_INFO("reflect and quit");
            self->quit();
            return self->last_dequeued();
        }
    );
}

void spawn5_server_impl(untyped_actor* self, actor client, group_ptr grp) {
    CPPA_LOGF_TRACE(CPPA_TARG(client, to_string)
                    << ", " << CPPA_TARG(grp, to_string));
    //FIXME spawn_in_group(grp, reflector);
    //FIXME spawn_in_group(grp, reflector);
    CPPA_LOGF_INFO("send {'Spawn5'} and await {'ok', actor_vector}");
    self->sync_send(client, atom("Spawn5"), grp).then(
        on(atom("ok"), arg_match) >> [=](const actor_vector& vec) {
            CPPA_LOGF_INFO("received vector with " << vec.size() << " elements");
            self->send(grp, "Hello reflectors!", 5.0);
            if (vec.size() != 5) {
                CPPA_PRINTERR("remote client did not spawn five reflectors!");
            }
            for (auto& a : vec) self->monitor(a);
        },
        others() >> [=] {
            CPPA_UNEXPECTED_MSG();
            self->quit(exit_reason::unhandled_exception);
        },
        after(chrono::seconds(10)) >> [=] {
            CPPA_UNEXPECTED_TOUT();
            self->quit(exit_reason::unhandled_exception);
        }
    )
    .continue_with([=] {
        CPPA_PRINT("wait for reflected messages");
        // receive seven reply messages (2 local, 5 remote)
        auto replies = std::make_shared<int>(0);
        self->become (
            on("Hello reflectors!", 5.0) >> [=] {
                if (++*replies == 7) {
                    CPPA_PRINT("wait for DOWN messages");
                    auto downs = std::make_shared<int>(0);
                    self->become (
                        on(atom("DOWN"), arg_match) >> [=](std::uint32_t reason) {
                            if (reason != exit_reason::normal) {
                                CPPA_PRINTERR("reflector exited for non-normal exit reason!");
                            }
                            if (++*downs == 5) {
                                CPPA_CHECKPOINT();
                                self->send(client, atom("Spawn5Done"));
                                self->quit();
                            }
                        },
                        others() >> [=] {
                            CPPA_UNEXPECTED_MSG();
                            self->quit(exit_reason::unhandled_exception);
                        },
                        after(chrono::seconds(2)) >> [=] {
                            CPPA_UNEXPECTED_TOUT();
                            self->quit(exit_reason::unhandled_exception);
                        }
                    );
                }
            },
            after(std::chrono::seconds(2)) >> [=] {
                CPPA_UNEXPECTED_TOUT();
                self->quit(exit_reason::unhandled_exception);
            }
        );
    });
}

// receive seven reply messages (2 local, 5 remote)
void spawn5_server(untyped_actor* self, actor client, bool inverted) {
    if (!inverted) spawn5_server_impl(self, client, group::get("local", "foobar"));
    else {
        CPPA_LOGF_INFO("request group");
        self->sync_send(client, atom("GetGroup")).then (
            [=](const group_ptr& remote_group) {
                spawn5_server_impl(self, client, remote_group);
            }
        );
    }
}

void spawn5_client(untyped_actor* self) {
    self->become (
        on(atom("GetGroup")) >> []() -> group_ptr {
            CPPA_LOGF_INFO("received {'GetGroup'}");
            return group::get("local", "foobar");
        },
        on(atom("Spawn5"), arg_match) >> [=](const group_ptr&) -> any_tuple {
            CPPA_LOGF_INFO("received {'Spawn5'}");
            actor_vector vec;
            for (int i = 0; i < 5; ++i) {
                //FIXME vec.push_back(spawn_in_group(grp, reflector));
            }
            return make_any_tuple(atom("ok"), std::move(vec));
        },
        on(atom("Spawn5Done")) >> [=] {
            CPPA_LOGF_INFO("received {'Spawn5Done'}");
            self->quit();
        }
    );
}

} // namespace <anonymous>

template<typename F>
void await_down(actor, F) {
    /*
    become (
        on(atom("DOWN"), arg_match) >> [=](uint32_t) -> bool {
            if (self->last_sender() == ptr) {
                continuation();
                return true;
            }
            return false; // not the 'DOWN' message we are waiting for
        }
    );
    */
}

static constexpr size_t num_pings = 10;

class client : public untyped_actor {

 public:

    client(actor server) : m_server(std::move(server)) { }

    behavior make_behavior() override {
        return spawn_ping();
    }

 private:

    behavior spawn_ping() {
        CPPA_PRINT("send {'SpawnPing'}");
        send(m_server, atom("SpawnPing"));
        return (
            on(atom("PingPtr"), arg_match) >> [=](const actor& ping) {
                auto pptr = spawn<monitored+detached+blocking_api>(pong, ping);
                await_down(pptr, [=] {
                    send_sync_msg();
                });
            }

        );
    }

    void send_sync_msg() {
        CPPA_PRINT("sync send {'SyncMsg', 4.2fSyncMsg}");
        sync_send(m_server, atom("SyncMsg"), 4.2f).then(
            on(atom("SyncReply")) >> [=] {
                send_foobars();
            }
        );
    }

    void send_foobars(int i = 0) {
        if (i == 0) { CPPA_PRINT("send foobars"); }
        if (i == 100) test_group_comm();
        else {
            CPPA_LOG_DEBUG("send message nr. " << (i+1));
            sync_send(m_server, atom("foo"), atom("bar"), i).then (
                on(atom("foo"), atom("bar"), i) >> [=] {
                    send_foobars(i+1);
                }
            );
        }
    }

    void test_group_comm() {
        CPPA_PRINT("test group communication via network");
        sync_send(m_server, atom("GClient")).then(
            on(atom("GClient"), arg_match) >> [=](actor gclient) {
                auto s5a = spawn<monitored>(spawn5_server, gclient, false);
                await_down(s5a, [=]{
                    test_group_comm_inverted();
                });
            }
        );
    }

    void test_group_comm_inverted() {
        CPPA_PRINT("test group communication via network (inverted setup)");
        become (
            on(atom("GClient")) >> [=]() -> any_tuple {
                auto cptr = last_sender();
                auto s5c = spawn<monitored>(spawn5_client);
                // set next behavior
                await_down(s5c, [=] {
                    CPPA_CHECKPOINT();
                    quit();
                });
                return make_any_tuple(atom("GClient"), s5c);
            }
        );
    }

    actor m_server;

};

class server : public untyped_actor {

 public:

    behavior make_behavior() override {
        return await_spawn_ping();
    }

 private:

    behavior await_spawn_ping() {
        CPPA_PRINT("await {'SpawnPing'}");
        return (
            on(atom("SpawnPing")) >> [=]() -> any_tuple {
                CPPA_PRINT("received {'SpawnPing'}");
                auto client = last_sender();
                CPPA_LOGF_ERROR_IF(!client, "last_sender() == nullptr");
                CPPA_LOGF_INFO("spawn event-based ping actor");
                auto pptr = spawn<monitored>(event_based_ping, num_pings);
                CPPA_LOGF_INFO("wait until spawned ping actor is done");
                await_down(pptr, [=] {
                    CPPA_CHECK_EQUAL(pongs(), num_pings);
                    await_sync_msg();
                });
                return make_any_tuple(atom("PingPtr"), pptr);
            }
        );
    }

    void await_sync_msg() {
        CPPA_PRINT("await {'SyncMsg'}");
        become (
            on(atom("SyncMsg"), arg_match) >> [=](float f) -> atom_value {
                CPPA_PRINT("received {'SyncMsg', " << f << "}");
                CPPA_CHECK_EQUAL(f, 4.2f);
                await_foobars();
                return atom("SyncReply");
            }
        );
    }

    void await_foobars() {
        CPPA_PRINT("await foobars");
        auto foobars = make_shared<int>(0);
        become (
            on(atom("foo"), atom("bar"), arg_match) >> [=](int i) -> any_tuple {
                ++*foobars;
                if (i == 99) {
                    CPPA_CHECK_EQUAL(*foobars, 100);
                    test_group_comm();
                }
                return last_dequeued();
            }
        );
    }

    void test_group_comm() {
        CPPA_PRINT("test group communication via network");
        become (
            on(atom("GClient")) >> [=]() -> any_tuple {
                auto cptr = last_sender();
                auto s5c = spawn<monitored>(spawn5_client);
                await_down(s5c, [=] {
                    //test_group_comm_inverted(cptr);
                });
                return make_any_tuple(atom("GClient"), s5c);
            }
        );
    }

    void test_group_comm_inverted(actor cptr) {
        CPPA_PRINT("test group communication via network (inverted setup)");
        sync_send(cptr, atom("GClient")).then (
            on(atom("GClient"), arg_match) >> [=](actor gclient) {
                await_down(spawn<monitored>(spawn5_server, gclient, true), [=] {
                    CPPA_CHECKPOINT();
                    quit();
                });
            }
        );
    }

};

int main(int argc, char** argv) {
    announce<actor_vector>();
    announce_tuple<atom_value, int>();
    announce_tuple<atom_value, atom_value, int>();
    string app_path = argv[0];
    bool run_remote_actor = true;
    if (argc > 1) {
        if (strcmp(argv[1], "run_remote_actor=false") == 0) {
            CPPA_LOGF_INFO("don't run remote actor");
            run_remote_actor = false;
        }
        else {
            run_client_part(get_kv_pairs(argc, argv), [](uint16_t port) {
                scoped_actor self;
                auto serv = remote_actor("localhost", port);
                // remote_actor is supposed to return the same server
                // when connecting to the same host again
                {
                    auto server2 = remote_actor("localhost", port);
                    CPPA_CHECK(serv == server2);
                    std::string localhost("127.0.0.1");
                    auto server3 = remote_actor(localhost, port);
                    CPPA_CHECK(serv == server3);
                }
                auto c = self->spawn<client, monitored>(serv);
                self->receive (
                    on(atom("DOWN"), arg_match) >> [=](uint32_t rsn) {
                        CPPA_CHECK_EQUAL(self->last_sender(), c);
                        CPPA_CHECK_EQUAL(rsn, exit_reason::normal);
                    }
                );
            });
            return CPPA_TEST_RESULT();
        }
    }
    CPPA_TEST(test_remote_actor);
    thread child;
    { // lifetime scope of self
        scoped_actor self;
        auto serv = self->spawn<server, monitored>();
        uint16_t port = 4242;
        bool success = false;
        do {
            try {
                publish(serv, port, "127.0.0.1");
                success = true;
                CPPA_LOGF_DEBUG("running on port " << port);
            }
            catch (bind_failure&) {
                // try next port
                ++port;
            }
        }
        while (!success);
        ostringstream oss;
        if (run_remote_actor) {
            oss << app_path << " run=remote_actor port=" << port << " &>/dev/null";
            // execute client_part() in a separate process,
            // connected via localhost socket
            child = thread([&oss]() {
                CPPA_LOGC_TRACE("NONE", "main$thread_launcher", "");
                string cmdstr = oss.str();
                if (system(cmdstr.c_str()) != 0) {
                    CPPA_PRINTERR("FATAL: command \"" << cmdstr << "\" failed!");
                    abort();
                }
            });
        }
        else { CPPA_PRINT("actor published at port " << port); }
        CPPA_CHECKPOINT();
        self->receive (
            on(atom("DOWN"), arg_match) >> [&](uint32_t rsn) {
                CPPA_CHECK_EQUAL(self->last_sender(), serv);
                CPPA_CHECK_EQUAL(rsn, exit_reason::normal);
            }
        );
    } // lifetime scope of self
    // wait until separate process (in sep. thread) finished execution
    await_all_actors_done();
    CPPA_CHECKPOINT();
    if (run_remote_actor) child.join();
    CPPA_CHECKPOINT();
    shutdown();
    return CPPA_TEST_RESULT();
}
