/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Thejas Kesari
* --------------------------------------------------------------------------*/
#include <cfloat>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <thread>
#include <unistd.h>

#include <json/json.hpp>

#include "common/types.h"
#include "common/key_manager.h"
#include "common/utils.h"
#include "atm/client.h"

using namespace impenn;
using namespace impenn::atm;
using json = nlohmann::json;

inline void print_error(const char *message) {
    if (config::VERBOSE) {
        std::cerr << "[ATM]: " << message << std::endl;
    }
}

inline void check_number(bool is_new_account) {
    std::string value(optarg);
    std::regex amount_format(config::AMOUNT_FORMAT);
    if (!std::regex_match(value, amount_format)) {
        print_error("invalid number");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }

    std::istringstream iss(value + ".");
    std::string dollar;
    std::getline(iss, dollar, '.');
    std::string cent;
    std::getline(iss, cent, '.');

    std::ostringstream oss;
    oss << config::MAX_AMOUNT;
    if (dollar.length() > oss.str().length()) {
        print_error("invalid number");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }

    uint64_t amount = 0;
    std::istringstream iss_dollar(dollar);
    iss_dollar >> amount;
    if (amount < config::MIN_AMOUNT
        || (amount == config::MIN_AMOUNT && cent == "00")
        || (is_new_account && amount < config::MIN_NEW_AMOUNT)
        || amount > config::MAX_AMOUNT) {
        print_error("invalid number");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }
}

int main(int argc, char *argv[]) {
    int s_flag = 0, i_flag = 0, p_flag = 0, c_flag = 0, a_flag = 0;
    int n_flag = 0, d_flag = 0, w_flag = 0, g_flag = 0;

    try {
        if (argc > config::MAX_SAFE_ARGC_ATM) {
            print_error("too many arguments");
            exit(config::ERROR_INVALID_ARGUMENTS);
        }

        for (int i = 0; argc > i; i++) {
            if (strnlen(argv[i], config::MAX_SAFE_ARG_LEN + 1) > config::MAX_SAFE_ARG_LEN) {
                print_error("argument exceeds maximum length");
                exit(config::ERROR_INVALID_ARGUMENTS);
            }
        }

        int opt;
        while ((opt = getopt(argc, argv, "s:i:p:c:a:n:d:w:g")) != -1) {
            switch (opt) {
                case 's': {

                    ++s_flag;
                    std::string value(optarg);
                    std::regex file_format(config::FILE_FORMAT);

                    if (!std::regex_match(value, file_format) || (value == ".") || (value == "..")) {
                        print_error("invalid auth file");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                    break;
                }

                case 'i': {
                    ++i_flag;
                    std::string value(optarg);
                    std::regex ip_format(config::IP_FORMAT);

                    if (!std::regex_match(value, ip_format)) {
                        print_error("invalid ip address");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                    break;
                }

                case 'p': {
                    ++p_flag;
                    char *end = nullptr;
                    long temp;
                    std::string value(optarg);
                    std::regex number("(0|[1-9][0-9]*)");
                    if (std::regex_match(value, number))
                        temp = strtol(optarg, &end, 10);
                    else {
                        print_error("invalid port number");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }

                    if (end == optarg || errno == ERANGE || temp < config::MIN_PORT || temp > config::MAX_PORT) {
                        print_error("port number is out of range");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                    break;
                }

                case 'a': {
                    ++a_flag;
                    std::string value(optarg);
                    if (value.length() > config::MAX_ACCOUNT_LEN) {
                        print_error("invalid account name");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                    std::regex file_format(config::FILE_FORMAT);

                    if (!std::regex_match(value, file_format)) {
                        print_error("invalid account name");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                    break;
                }

                case 'c': {
                    ++c_flag;
                    std::string value(optarg);
                    std::regex file_format(config::FILE_FORMAT);

                    if (!std::regex_match(value, file_format) || (value == ".") || (value == "..")) {
                        print_error("invalid auth file");
                        exit(config::ERROR_INVALID_ARGUMENTS);
                    }
                    break;
                }

                case 'n': {
                    ++n_flag;
                    check_number(true);
                    break;
                }

                case 'd': {
                    ++d_flag;
                    check_number(false);
                    break;
                }

                case 'w': {
                    ++w_flag;
                    check_number(false);
                    break;
                }

                case 'g':
                    ++g_flag;
                    if (optind != argc) {
                        if (strncmp(argv[optind], "-", 1) != 0) {
                            print_error("invalid arguments");
                            exit(config::ERROR_INVALID_ARGUMENTS);
                        }
                    }
                    break;

                default:
                    print_error("invalid arguments");
                    exit(config::ERROR_INVALID_ARGUMENTS);
            }
        }

        if ((a_flag == 0) || ((n_flag + w_flag + d_flag + g_flag) != 1)) {
            print_error("too many or too few mandatory input options");
            exit(config::ERROR_INVALID_ARGUMENTS);
        }

        if ((s_flag > 1) || (i_flag > 1) || (p_flag > 1) || (c_flag > 1) || (a_flag > 1) || (n_flag > 1) ||
            (d_flag > 1) ||
            (w_flag > 1) || (g_flag > 1)) {
            print_error("duplicated option");
            exit(config::ERROR_INVALID_ARGUMENTS);
        }

    }
    catch (const std::exception &e) {
        print_error("invalid arguments");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }

    std::string bank_address = std::string(config::DEFAULT_ADDRESS);
    int port = config::DEFAULT_PORT;
    std::string account_name;
    std::string auth_file = std::string(config::DEFAULT_AUTH_FILE_NAME);
    std::string card_file;
    std::string dollars = "0";
    std::string cents = "00";

    try {
        optind = 0;
        int opt;
        while ((opt = getopt(argc, argv, "s:i:p:c:a:n:d:w:g")) != -1) {
            switch (opt) {
                case 's': {
                    auth_file = std::string(optarg);
                    break;
                }

                case 'i': {
                    bank_address = std::string(optarg);
                    break;
                }

                case 'p': {
                    port = atoi(optarg);
                    break;
                }

                case 'a': {
                    account_name = std::string(optarg);
                    break;
                }

                case 'c': {
                    card_file = std::string(optarg);
                    break;
                }

                case 'n':
                case 'd':
                case 'w': {
                    std::string amount = std::string(optarg);
                    std::istringstream iss(amount);
                    std::getline(iss, dollars, '.');
                    std::getline(iss, cents, '.');
                    break;
                }

                case 'g':
                    break;

                default:
                    print_error("invalid arguments");
                    exit(config::ERROR_INVALID_ARGUMENTS);
            }
        }
    } catch (const std::exception &e) {
        print_error("invalid arguments");
        exit(config::ERROR_INVALID_ARGUMENTS);
    }

    if (card_file.empty()) {
        card_file = account_name + config::DEFAULT_CARD_FILE_EXT;
    }

    int status = KeyManager::get().load_auth_file(auth_file.c_str());
    if (status != 0) exit(status);

    if (n_flag > 0) {
        status = KeyManager::get().generate_card_file(account_name.c_str(), card_file.c_str());
        if (status != 0) exit(config::ERROR_ATM_CARD_FILE_EXIST);
    } else {
        status = KeyManager::get().verify_card_file(account_name.c_str(), card_file.c_str());
        if (status != 0) exit(status);
    }

    std::string message;
    MessageType command = MessageType::unknown;
    if (n_flag > 0) {
        command = MessageType::client_new_account;
    } else if (d_flag > 0) {
        command = MessageType::client_deposit;
    } else if (w_flag > 0) {
        command = MessageType::client_withdraw;
    } else if (g_flag > 0) {
        command = MessageType::client_balance;
    }

    try {
        json atm_to_bank;
        atm_to_bank[config::JSON_KEY_MESSAGE_TYPE] = command;
        atm_to_bank[config::JSON_KEY_ACCOUNT] = account_name;
        atm_to_bank[config::JSON_KEY_DOLLARS] = dollars;
        atm_to_bank[config::JSON_KEY_CENTS] = cents;

        message = atm_to_bank.dump();
    } catch (const std::exception &e) {
        print_error("failed to generate json message");
        return config::ERROR_UNKNOWN;
    }

    Client client;
    auto start = std::chrono::system_clock::now();
    while (true) {
        status = client.connect_to_bank(bank_address.c_str(), port);
        if (status == 0) break;

        auto current = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = current - start;
        if (elapsed_seconds.count() < config::CONNECT_TIMEOUT) {
            print_error("failed to connect to bank - retry in 1 second");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } else {
            print_error("failed to connect to bank - timeout");
            if (command == MessageType::client_new_account) {
                KeyManager::get().delete_card_file(card_file.c_str());
            }
            exit(config::ERROR_ATM_FAILED_CONNECT);
        }
    }

    status = client.write_message(message);
    if (status != 0) {
        if (command == MessageType::client_new_account) {
            KeyManager::get().delete_card_file(card_file.c_str());
        }
        exit(status);
    }

    std::string results = client.read_message(&status);
    if (status != 0) {
        if (command == MessageType::client_new_account) {
            KeyManager::get().delete_card_file(card_file.c_str());
        }
        exit(status);
    }
    if (results.empty()) {
        if (command == MessageType::client_new_account) {
            KeyManager::get().delete_card_file(card_file.c_str());
        }
        exit(config::ERROR_PROTOCOL);
    }

    print_error(std::string("received message: " + results).c_str());

    try {
        json json_results = json::parse(results);

        if (json_results.size() > config::NUM_BANK_JSON_KEYS) exit(config::ERROR_PROTOCOL);
        if (json_results.find(config::JSON_KEY_MESSAGE_TYPE) == json_results.end()
            || (json_results[config::JSON_KEY_MESSAGE_TYPE] == MessageType::bank_failed
                && command == MessageType::unknown)
            || json_results.find(config::JSON_KEY_ACCOUNT) == json_results.end()
            || json_results.find(config::JSON_KEY_DOLLARS) == json_results.end()
            || json_results.find(config::JSON_KEY_CENTS) == json_results.end()) {
            exit(config::ERROR_PROTOCOL);
        } else if (json_results[config::JSON_KEY_MESSAGE_TYPE] == MessageType::bank_failed
                   && command != MessageType::unknown) {
            exit(config::ERROR_UNKNOWN);
        }

        std::ostringstream os;
        os << json_results[config::JSON_KEY_DOLLARS].get<std::string>() << "."
           << std::setfill('0') << std::setw(2) << (int) json_results[config::JSON_KEY_CENTS];

        json output;
        output[config::JSON_KEY_ACCOUNT] = json_results[config::JSON_KEY_ACCOUNT].get<std::string>();
        if (n_flag > 0) {
            output[config::JSON_KEY_INIT_BALANCE] = os.str();
        } else if (d_flag > 0) {
            output[config::JSON_KEY_DEPOSIT] = os.str();
        } else if (w_flag > 0) {
            output[config::JSON_KEY_WITHDRAW] = os.str();
        } else if (g_flag > 0) {
            output[config::JSON_KEY_BALANCE] = os.str();
        }

        std::cout << utils::remove_amount_quotes(output.dump()) << std::endl;
    } catch (const std::exception &e) {
        print_error("failed to parse bank results");
        if (command == MessageType::client_new_account) {
            KeyManager::get().delete_card_file(card_file.c_str());
        }
        exit(config::ERROR_PROTOCOL);
    }

    return 0;
}

