/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#include "server.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>

#include "common/key_manager.h"
#include "driver.h"

using namespace impenn;
using namespace impenn::bank;

std::vector<std::thread> impenn::bank::Server::running_threads;
std::mutex impenn::bank::Server::thread_mutex;

std::atomic_bool impenn::bank::Server::interrupted;

impenn::bank::Server::Server() {
    interrupted = false;
}

impenn::bank::Server::~Server() {
    if (ctx != nullptr) SSL_CTX_free(ctx);
}

int impenn::bank::Server::start(int port) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = shutdown;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    sigaction(config::TERMINATE_SIGNAL, &action, nullptr);

    if (!KeyManager::get().is_ready()) {
        print_error("failed to start", "KeyManager is not ready");
        return config::ERROR_INVALID_STATE;
    }

    ctx = KeyManager::get().create_tls_context();
    if (ctx == nullptr) {
        print_error("failed to start", "cannot create context");
        return config::ERROR_ATM_INVALID_AUTH_FILE;
    }

    int bank_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (bank_fd < 0) {
        print_error("failed to start", "cannot open socket");
        return config::ERROR_UNKNOWN;
    }

    int reuse_address = 1;
    setsockopt(bank_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address));

    struct sockaddr_in bank_addr;
    bzero(&bank_addr, sizeof(bank_addr));
    bank_addr.sin_family = AF_INET;
    bank_addr.sin_addr.s_addr = htons(INADDR_ANY);
    bank_addr.sin_port = htons(port);

    if (bind(bank_fd, (struct sockaddr *) &bank_addr, sizeof(bank_addr)) < 0) {
        print_error("failed to bind", strerror(errno));
        return config::ERROR_UNKNOWN;
    }
    if (listen(bank_fd, config::SOCKET_BACKLOG) < 0) {
        print_error("failed to start listen", strerror(errno));
        return config::ERROR_UNKNOWN;
    }

    auto db = std::make_shared<Database>();
    fd_set read_socket_set;

    while (true) {
        if (interrupted) {
            print_error("interrupted");
            break;
        }

        FD_ZERO(&read_socket_set);
        FD_SET(bank_fd, &read_socket_set);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 250000;
        int ready = select(bank_fd + 1, &read_socket_set, nullptr, nullptr, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                interrupted = true;
                print_error("interrupted");
                break;
            } else {
                print_error("error during listening", strerror(errno));
                return config::ERROR_PROTOCOL;
            }
        }
        if (ready == 0) {
            continue;
        }

        if (FD_ISSET(bank_fd, &read_socket_set)) {
            struct sockaddr_in atm_addr;
            socklen_t atm_addr_len = sizeof(atm_addr);
            int client_fd = accept(bank_fd, (struct sockaddr *) &atm_addr, &atm_addr_len);

            char name_buffer[INET_ADDRSTRLEN];
            std::string client_name = "unknown";
            if (inet_ntop(AF_INET, &atm_addr.sin_addr.s_addr, name_buffer, sizeof(name_buffer)) != nullptr) {
                std::ostringstream stream;
                stream << name_buffer << ":" << ntohs(atm_addr.sin_port) << " with fd = " << std::to_string(client_fd);
                client_name = stream.str();
                print_error("incoming request from", client_name.c_str());
            }

            auto talker = std::make_shared<Talker>(client_fd, client_name);
            if (talker->accept(ctx) != 0) {
                std::ostringstream os;
                os << "TLS handshake failed with " << name_buffer << ":" << ntohs(atm_addr.sin_port);
                std::cout << config::PROTOCOL_ERR_STR << std::endl;
                print_error(os.str().c_str());

                continue;
            }

            {
                std::lock_guard<std::mutex> lock(thread_mutex);
                running_threads.emplace_back(std::thread(worker, talker, db));
            }
        }
    }

    {
        for (auto &&thread : running_threads) {
            thread.join();
        }
    }

    return 0;
}

void impenn::bank::Server::worker(std::shared_ptr<Talker> talker, std::shared_ptr<Database> db) {
    Driver driver(std::move(talker), std::move(db));
    driver.start();

    {
        std::lock_guard<std::mutex> lock(thread_mutex);
        auto id = std::this_thread::get_id();
        auto iter = std::find_if(running_threads.begin(), running_threads.end(),
                                 [=](std::thread &t) { return (t.get_id() == id); });
        if (iter != running_threads.end()) {
            iter->detach();
            running_threads.erase(iter);
        }
    }
}

void impenn::bank::Server::print_error(const char *message, const char *error) {
    if (config::VERBOSE) {
        std::cerr << "[BANK]: " << message << " - " << error << std::endl;
    }
}

void impenn::bank::Server::print_error(const char *message) {
    if (config::VERBOSE) {
        std::cerr << "[BANK]: " << message << std::endl;
    }
}

void impenn::bank::Server::shutdown(int sig) {
    interrupted = true;
}
