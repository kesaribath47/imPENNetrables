/* ---------------------------------------------------------------------------
 * This file is part of imPENNetrables
 *
 * @author: Grayson Honan
 * --------------------------------------------------------------------------*/
#include "driver.h"

#include <iostream>
#include <thread>

#include <json/json.hpp>

#include "common/utils.h"
#include "bank/sanitizer.h"

using namespace impenn;
using namespace impenn::bank;
using json = nlohmann::json;

impenn::bank::Driver::Driver(std::shared_ptr<Talker> talker, std::shared_ptr<Database> db)
        : talker(std::move(talker)), db(std::move(db)) {

}

void impenn::bank::Driver::start() {
    int status = 0;
    std::string message;
    Sanitizer sanitizer;

    Account accountReturn;
    accountReturn.dollars = 0;
    accountReturn.cents = 0;

    bool result = false;
    message = talker->read_message(&status);

    if (status == 0 && message.length() > 0) {
        print_error("received message", message.c_str());
    } else {
        std::cout << config::PROTOCOL_ERR_STR << std::endl;
        return;
    }

    MessageType type;
    try {
        type = sanitizer.check_command(message);
    }
    catch (const std::exception &e) {
        std::cout << config::PROTOCOL_ERR_STR << std::endl;
        type = MessageType::unknown;
    }

    if (type != MessageType::unknown) {
        json jsonMessage = json::parse(message);
        int64_t dollars = parseDollars(jsonMessage[config::JSON_KEY_DOLLARS].get<std::string>().c_str());
        int16_t cents = parseCents(jsonMessage[config::JSON_KEY_CENTS].get<std::string>().c_str());
        if (dollars < 0 || cents < 0) {
            print_error("failed to parse dollars and cents", "invalid numbers");
            std::cout << config::PROTOCOL_ERR_STR << std::endl;
            return;
        }

        switch (type) {
            case MessageType::client_deposit: {
                if (dollars == 0 && cents == 0) {
                    print_error("dollars and cents can't both be 0", "invalid numbers");
                    std::cout << config::PROTOCOL_ERR_STR << std::endl;
                    break;
                }

                result = db->deposit(jsonMessage[config::JSON_KEY_ACCOUNT].get<std::string>(),
                                     dollars, cents,
                                     &accountReturn);
            }
                break;
            case MessageType::client_withdraw: {
                if (dollars == 0 && cents == 0) {
                    print_error("dollars and cents can't both be 0", "invalid numbers");
                    std::cout << config::PROTOCOL_ERR_STR << std::endl;
                    break;
                }
                result = db->withdraw(jsonMessage[config::JSON_KEY_ACCOUNT].get<std::string>(),
                                      dollars, cents,
                                      &accountReturn);
            }
                break;
            case MessageType::client_new_account: {
                if (dollars < config::MIN_STARTING_BALANCE) {
                    print_error("initial balance must be > $10.00", "invalid numbers");
                    std::cout << config::PROTOCOL_ERR_STR << std::endl;
                    break;
                }
                result = db->create_account(jsonMessage[config::JSON_KEY_ACCOUNT].get<std::string>(),
                                            dollars, cents,
                                            &accountReturn);
            }
                break;
            case MessageType::client_balance:
                if (dollars != 0 && cents != 0) {
                    print_error("dollars and cents should both be 0", "invalid numbers");
                    std::cout << config::PROTOCOL_ERR_STR << std::endl;
                    break;
                }
                result = db->balance(jsonMessage[config::JSON_KEY_ACCOUNT].get<std::string>(), &accountReturn);
                break;
            default:
                print_error("failed to handle command", "invalid command type");
                std::cout << config::PROTOCOL_ERR_STR << std::endl;
                result = false;
                break;
        }
    }

    if (sendResult(result, &accountReturn) > 0) return;
    if (result && type != MessageType::unknown) printResult(&accountReturn, type);
}

void impenn::bank::Driver::printResult(impenn::Account *accountReturn, impenn::MessageType type) {
    switch (type) {
        case MessageType::client_deposit: {
            // {"account":"55555","deposit":20.00}
            json deposit;
            deposit[config::JSON_KEY_ACCOUNT] = accountReturn->name;
            std::stringstream deposit_stream;
            deposit_stream << accountReturn->dollars.get_str() << "." << std::setfill('0') << std::setw(2)
                           << ((int) accountReturn->cents);
            std::string balance = deposit_stream.str();
            deposit[config::JSON_KEY_DEPOSIT] = balance;
            std::cout << utils::remove_amount_quotes(deposit.dump()) << std::endl;
        }

            break;
        case MessageType::client_withdraw: {
            json withdraw;
            withdraw[config::JSON_KEY_ACCOUNT] = accountReturn->name;
            std::stringstream withdraw_stream;
            withdraw_stream << accountReturn->dollars.get_str() << "." << std::setfill('0') << std::setw(2)
                            << ((int) accountReturn->cents);
            std::string balance = withdraw_stream.str();
            withdraw[config::JSON_KEY_WITHDRAW] = balance;
            std::cout << utils::remove_amount_quotes(withdraw.dump()) << std::endl;
        }

            break;
        case MessageType::client_new_account: {
            json new_account;
            new_account[config::JSON_KEY_ACCOUNT] = accountReturn->name;
            std::stringstream init_bal_stream;
            init_bal_stream << accountReturn->dollars.get_str() << "." << std::setfill('0') << std::setw(2)
                            << ((int) accountReturn->cents);
            std::string init_bal = init_bal_stream.str();
            new_account[config::JSON_KEY_INIT_BALANCE] = init_bal;
            std::cout << utils::remove_amount_quotes(new_account.dump()) << std::endl;
        }
            break;
        case MessageType::client_balance: {
            json check_bal;
            check_bal[config::JSON_KEY_ACCOUNT] = accountReturn->name;
            std::stringstream check_bal_stream;
            check_bal_stream << accountReturn->dollars.get_str() << "." << std::setfill('0') << std::setw(2)
                             << ((int) accountReturn->cents);
            std::string balance = check_bal_stream.str();
            check_bal[config::JSON_KEY_BALANCE] = balance;
            std::cout << utils::remove_amount_quotes(check_bal.dump()) << std::endl;
        }

            break;
        default:
            print_error("this should never happen!", "invalid type");
            break;
    }
}

int impenn::bank::Driver::sendResult(bool result, impenn::Account *accountReturn) {
    int status = 0;

    try {
        json message;
        message[config::JSON_KEY_ACCOUNT] = accountReturn->name;
        message[config::JSON_KEY_DOLLARS] = accountReturn->dollars.get_str();
        message[config::JSON_KEY_CENTS] = accountReturn->cents;

        if (result) {
            message[config::JSON_KEY_MESSAGE_TYPE] = MessageType::bank_success;
        } else {
            message[config::JSON_KEY_MESSAGE_TYPE] = MessageType::bank_failed;
        }

        if (talker->write_message(message.dump()) > 0) {
            std::cout << config::PROTOCOL_ERR_STR << std::endl;
            status = config::ERROR_UNKNOWN;
        }
    } catch (const std::exception &e) {
        std::cout << config::PROTOCOL_ERR_STR << std::endl;
        status = config::ERROR_UNKNOWN;
    }

    if (status != 0) return status;

    std::string holder = talker->read_message(&status);
    return 0;
}

int64_t impenn::bank::Driver::parseDollars(const char *number) {
    char *end = nullptr;
    uint32_t dollars;

    errno = 0;
    dollars = (uint32_t) strtoul(number, &end, 10);

    if (end != number && errno != ERANGE) return dollars;

    return -1;
}

int16_t impenn::bank::Driver::parseCents(const char *number) {
    char *end = nullptr;
    uint8_t cents;

    errno = 0;
    cents = (uint8_t) strtoul(number, &end, 10);

    if (end != number && errno != ERANGE) return cents;

    return -1;
}

void impenn::bank::Driver::print_error(const char *message, const char *error) {
    if (config::VERBOSE) {
        std::cerr << "[BANK-Driver-" << std::this_thread::get_id() << "]: " << message << " - " << error << std::endl;
    }
}
