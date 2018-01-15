/* ---------------------------------------------------------------------------
 * This file is part of imPENNetrables
 *
 * @author: Grayson Honan
 * --------------------------------------------------------------------------*/

#include <iostream>
#include <regex>
#include <unistd.h>

#include "common/key_manager.h"
#include "bank/server.h"

using namespace impenn;
using namespace impenn::bank;

inline void print_error(const char *message) {
    if (config::VERBOSE) {
        std::cerr << "[BANK]: " << message << std::endl;
    }
}

inline void pArg(int *port) {
    char *end = nullptr;
    long temp;
    std::string s(optarg);
    std::regex number(config::NUMBER_FORMAT);

    if (std::regex_match(s, number)) {
        errno = 0;
        temp = strtol(optarg, &end, 10);
    } else {
        print_error("number must match /(0|[1-9][0-9]*)/");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }


    if (end != optarg && errno != ERANGE && temp >= config::MIN_PORT && temp <= config::MAX_PORT) {
        *port = (int) temp;
    } else {
        print_error("port must be between 1024 and 65535 inclusively");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }
}

inline void sArg(std::string &auth_file) {
    std::string s(optarg);
    std::regex file_format(config::FILE_FORMAT);

    if (std::regex_match(s, file_format) && s.compare(".") != 0 && s.compare("..") != 0) {
        auth_file = strdup(optarg);
    } else {
        print_error("File must match /[_\\-\\.0-9a-z]/ and can't be . or ..");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }

}

int main(int argc, char *argv[]) {

    bool pVisited = false;
    bool sVisited = false;

    int port = config::DEFAULT_PORT;
    std::string auth_file(config::DEFAULT_AUTH_FILE_NAME);

    try {
        char opt = 0;
        int i = 0;
        if (argc > config::MAX_SAFE_ARGC_BANK) {
            print_error("too many arguments");
            exit(config::ERROR_INVALID_ARGUMENTS);
        }
        for (i = 0; argc > i; i++) {
            if (strnlen(argv[i], config::MAX_SAFE_ARG_LEN + 1) > config::MAX_SAFE_ARG_LEN) {
                print_error("argument exceeds maximum length");
                exit(config::ERROR_INVALID_ARGUMENTS);
            }
        }

        while ((opt = (char) getopt(argc, argv, "p:s:")) != -1) {
            switch (opt) {
                case 'p':
                    if (!pVisited) {
                        pArg(&port);
                        pVisited = true;
                    } else {
                        print_error("duplicated option p");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                    break;
                case 's': {
                    if (!sVisited) {
                        sArg(auth_file);
                        sVisited = true;
                    } else {
                        print_error("duplicated option s");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                }
                    break;

                default: /* '?' */
                    print_error("usage: bank [-p <port>] [-s <auth-file>]");
                    exit(config::ERROR_INVALID_ARGUMENTS);
            }
        }
    }
    catch (const std::exception &e) {
        print_error("usage: bank [-p <port>] [-s <auth-file>]");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }

    int status = KeyManager::get().generate_auth_file(auth_file.c_str());
    if (status != 0) exit(status);

    std::ostringstream os;
    os << "starting on port " << port << " with auth file " << auth_file;
    print_error(os.str().c_str());

    Server server;
    server.start(port);

    return 0;
}
