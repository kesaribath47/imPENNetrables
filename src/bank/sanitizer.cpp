/* ---------------------------------------------------------------------------
 * This file is part of imPENNetrables
 *
 * @author: Grayson Honan
 * --------------------------------------------------------------------------*/
#include "sanitizer.h"

#include <iostream>
#include <regex>

using namespace impenn;
using namespace impenn::bank;
using json = nlohmann::json;

impenn::MessageType impenn::bank::Sanitizer::check_command(std::string input) {
    impenn::MessageType return_code = impenn::MessageType::unknown;
    json jInput = json::parse(input);

    std::ostringstream os;
    os << "jInput command is "
       << jInput[config::JSON_KEY_MESSAGE_TYPE];
    print_error(os.str().c_str());

    if (jInput[config::JSON_KEY_MESSAGE_TYPE].get<int>() == (int) MessageType::client_deposit) {
        return_code = check_deposit_cmd(jInput);
    } else if (jInput[config::JSON_KEY_MESSAGE_TYPE].get<int>() == (int) MessageType::client_withdraw) {
        return_code = check_withdraw_cmd(jInput);
    } else if (jInput[config::JSON_KEY_MESSAGE_TYPE].get<int>() == (int) MessageType::client_new_account) {
        return_code = check_new_account_cmd(jInput);
    } else if (jInput[config::JSON_KEY_MESSAGE_TYPE].get<int>() == (int) MessageType::client_balance) {
        return_code = check_balance_cmd(jInput);
    }

    return return_code;
}

impenn::MessageType impenn::bank::Sanitizer::check_regular_cmd(impenn::MessageType type,
                                                               std::string account,
                                                               std::string dollars,
                                                               std::string cents) {

    std::regex format(config::FILE_FORMAT);
    if (!std::regex_match(account, format)) {
        print_error("Account regex failed");
        type = MessageType::unknown;
    }

    format.assign(config::NUMBER_FORMAT);
    if (!std::regex_match(dollars, format)) {
        print_error("DOLLARS regex failed");
        type = MessageType::unknown;
    }

    format.assign(config::FRACTION_FORMAT);
    if (!std::regex_match(cents, format)) {
        print_error("CENTS regex failed");
        type = MessageType::unknown;
    }

    return type;
}

impenn::MessageType impenn::bank::Sanitizer::check_deposit_cmd(nlohmann::json deposit) {
    MessageType return_code = MessageType::client_deposit;
    std::ostringstream os;
    os << "Deposit is for "
       << deposit[config::JSON_KEY_ACCOUNT] << "'s account. The amount is $"
       << deposit[config::JSON_KEY_DOLLARS] << "." << deposit[config::JSON_KEY_CENTS];
    print_error(os.str().c_str());

    if (deposit.size() != config::NUM_DEPOSIT_JSON_KEYS) {
        return_code = MessageType::unknown;
        print_error("incorrect number of keys");
    } else {
        return_code = check_regular_cmd(return_code, deposit[config::JSON_KEY_ACCOUNT].get<std::string>(),
                                        deposit[config::JSON_KEY_DOLLARS].get<std::string>(),
                                        deposit[config::JSON_KEY_CENTS].get<std::string>());
    }

    return return_code;
}

impenn::MessageType impenn::bank::Sanitizer::check_withdraw_cmd(nlohmann::json withdraw) {
    MessageType return_code = MessageType::client_withdraw;
    std::ostringstream os;
    os << "Withdraw is from "
       << withdraw[config::JSON_KEY_ACCOUNT] << "'s account. The amount is $"
       << withdraw[config::JSON_KEY_DOLLARS] << "." << withdraw[config::JSON_KEY_CENTS];
    print_error(os.str().c_str());

    if (withdraw.size() != config::NUM_WITHDRAW_JSON_KEYS) {
        return_code = MessageType::unknown;
        print_error("incorrect number of keys");
    } else {
        return_code = check_regular_cmd(return_code, withdraw[config::JSON_KEY_ACCOUNT].get<std::string>(),
                                        withdraw[config::JSON_KEY_DOLLARS].get<std::string>(),
                                        withdraw[config::JSON_KEY_CENTS].get<std::string>());
    }

    return return_code;
}

impenn::MessageType impenn::bank::Sanitizer::check_new_account_cmd(nlohmann::json newAccount) {
    MessageType return_code = MessageType::client_new_account;
    std::ostringstream os;
    os << "New account for "
       << newAccount[config::JSON_KEY_ACCOUNT] << ". The initial balance is $"
       << newAccount[config::JSON_KEY_DOLLARS] << "." << newAccount[config::JSON_KEY_CENTS];
    print_error(os.str().c_str());

    if (newAccount.size() != config::NUM_NEW_ACCOUNT_JSON_KEYS) {
        return_code = MessageType::unknown;
        print_error("incorrect number of keys");
    } else {
        return_code = check_regular_cmd(return_code, newAccount[config::JSON_KEY_ACCOUNT].get<std::string>(),
                                        newAccount[config::JSON_KEY_DOLLARS].get<std::string>(),
                                        newAccount[config::JSON_KEY_CENTS].get<std::string>());
    }


    return return_code;
}

impenn::MessageType impenn::bank::Sanitizer::check_balance_cmd(nlohmann::json balance) {
    MessageType return_code = MessageType::client_balance;
    std::ostringstream os;
    os << "Balance check is for "
       << balance[config::JSON_KEY_ACCOUNT] << "'s account.";
    print_error(os.str().c_str());

    if (balance.size() != config::NUM_CHECK_BALANCE_JSON_KEYS) {
        return_code = MessageType::unknown;
        print_error("incorrect number of keys");
    } else {
        return_code = check_regular_cmd(return_code, balance[config::JSON_KEY_ACCOUNT].get<std::string>(),
                                        balance[config::JSON_KEY_DOLLARS].get<std::string>(),
                                        balance[config::JSON_KEY_CENTS].get<std::string>());
    }

    return return_code;
}

void impenn::bank::Sanitizer::print_error(const char *message) {
    if (config::VERBOSE) {
        std::cerr << "[BANK-Sanitizer] " << message << std::endl;
    }
}