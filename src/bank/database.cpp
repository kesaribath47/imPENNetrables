/* ---------------------------------------------------------------------------
 * This file is part of imPENNetrables
 *
 * @author: Grayson Honan
 * --------------------------------------------------------------------------*/
#include "database.h"

#include <iostream>
#include <sstream>

using namespace impenn;
using namespace impenn::bank;

bool impenn::bank::Database::deposit(std::string account,
                                     uint32_t dollars,
                                     uint8_t cents,
                                     impenn::Account *accountReturn) {
    std::lock_guard<std::mutex> lock(dbLock);

    if (dbDollars.count(account)) {
        mpz_class d = dollars;
        dbDollars[account] += d;
        dbCents[account] += cents;
        if (dbCents[account] >= config::CENTS_PER_DOLLAR) {
            dbCents[account] -= config::CENTS_PER_DOLLAR;
            dbDollars[account] += 1;
        }

        std::ostringstream os;
        os << "New balance is "
           << dbDollars[account].get_str() << "." << ((int) dbCents[account]);
        print_error(os.str().c_str());

        accountReturn->name = account;
        accountReturn->dollars = dollars;
        accountReturn->cents = cents;

        return true;
    } else {
        print_error("failed to get balance", "no such account");
        return false;
    }

}

bool
impenn::bank::Database::withdraw(std::string account, uint32_t dollars, uint8_t cents, impenn::Account *accountReturn) {
    std::lock_guard<std::mutex> lock(dbLock);

    mpz_class d = dollars;
    if (dbDollars.count(account)) {
        if (dbCents[account] < cents) {
            dbDollars[account] -= 1;
            dbCents[account] += config::CENTS_PER_DOLLAR;
        }
        dbCents[account] -= cents;
        dbDollars[account] -= d;
        if (dbCents[account] >= 0 && dbCents[account] <= 99 && dbDollars[account] >= 0) {
            std::ostringstream os;
            os << "New balance is "
               << dbDollars[account].get_str() << "." << ((int) dbCents[account]);
            print_error(os.str().c_str());

            accountReturn->name = account;
            accountReturn->dollars = dollars;
            accountReturn->cents = cents;
            return true;
        } else {
            dbDollars[account] += d;
            dbCents[account] += cents;
            if (dbCents[account] >= config::CENTS_PER_DOLLAR) {
                dbDollars[account] += 1;
                dbCents[account] -= config::CENTS_PER_DOLLAR;
            }
            accountReturn->name = account;
            accountReturn->dollars = dollars;
            accountReturn->cents = cents;
        }
    }

    print_error("failed to withdraw", "no such account, or insufficient funds");
    return false;

}

bool impenn::bank::Database::create_account(std::string account, uint32_t dollars, uint8_t cents,
                                            impenn::Account *accountReturn) {

    std::lock_guard<std::mutex> lock(dbLock);
    if (dbDollars.count(account)) {
        print_error("failed to create account", "account already exists");
        return false;
    } else {
        mpz_class d = dollars;
        dbDollars.insert(std::pair<std::string, mpz_class>(account, dollars));
        dbCents.insert(std::pair<std::string, uint8_t>(account, cents));

        std::ostringstream os;
        os << "New balance is "
           << dbDollars[account].get_str() << "." << ((int) dbCents[account]);
        print_error(os.str().c_str());

        accountReturn->name = account;
        accountReturn->dollars = dbDollars[account];
        accountReturn->cents = dbCents[account];
        return true;
    }

}

bool impenn::bank::Database::balance(std::string account, impenn::Account *accountReturn) {

    std::lock_guard<std::mutex> lock(dbLock);
    if (dbDollars.count(account)) {
        std::ostringstream os;
        os << "Balance is "
           << dbDollars[account].get_str() << "." << ((int) dbCents[account]);
        print_error(os.str().c_str());

        accountReturn->name = account;
        accountReturn->dollars = dbDollars[account];
        accountReturn->cents = dbCents[account];
        return true;
    } else {
        print_error("failed to get balance", "no such account");
        return false;
    }

}

void impenn::bank::Database::print_error(const char *message, const char *error) {
    if (config::VERBOSE) {
        std::cerr << "[BANK-Database]: " << message << " - " << error << std::endl;
    }
}

void impenn::bank::Database::print_error(const char *message) {
    if (config::VERBOSE) {
        std::cerr << "[BANK-Database]: " << message << std::endl;
    }
}
