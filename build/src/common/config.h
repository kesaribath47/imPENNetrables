/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: The imPENNetrables
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_CONFIG_H
#define IMPENNETRABLES_CONFIG_H

#include <csignal>
#include <string>

#include <openssl/obj_mac.h>

namespace impenn {
namespace config {

const int ELLIPTIC_CURVE = NID_secp384r1;
const unsigned char *const NAME_C = (unsigned char *) "US";
const unsigned char *const NAME_O = (unsigned char *) "imPENNetrables";
const long CERT_DURATION = 21600;

const bool OVERWRITE_AUTH_FILE = false;
const bool OVERWRITE_CARD_FILE = false;
const bool VERBOSE = false;
const int MAX_CARD_FILE_LENGTH = 1024;
const int TERMINATE_SIGNAL = SIGTERM;
const int SOCKET_BACKLOG = 10;
const int CONNECT_TIMEOUT = 0;
const int SOCKET_TIMEOUT = 10;
const int MAX_TLS_BUFFER_SIZE = 16384;
const int MAX_SAFE_ARGC_BANK = 5;
const int MAX_SAFE_ARGC_ATM = 13;
const int MAX_SAFE_ARG_LEN = 205;
const int MAX_ACCOUNT_LEN = 200;
const int MIN_PORT = 1024;
const int MAX_PORT = 65535;
const uint64_t MIN_AMOUNT = 0;
const uint64_t MIN_NEW_AMOUNT = 10;
const uint64_t MAX_AMOUNT = 4294967295;
const uint32_t MIN_STARTING_BALANCE = 10;
const uint8_t CENTS_PER_DOLLAR = 100;

const char *const NUMBER_FORMAT = "(0|[1-9][0-9]*)";
const char *const FILE_FORMAT = "[_\\.0-9a-z-]+";
const char *const FRACTION_FORMAT = "[0-9]{2}";
const char *const IP_FORMAT = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])";
const char *const AMOUNT_FORMAT = "(0|[1-9][0-9]*)\\.[0-9][0-9]";

const char *const DEFAULT_ADDRESS = "127.0.0.1";
const int DEFAULT_PORT = 3000;
const char *const DEFAULT_AUTH_FILE_NAME = "bank.auth";
const char *const DEFAULT_CARD_FILE_EXT = ".card";

const char *const JSON_KEY_MESSAGE_TYPE = "message_type";
const char *const JSON_KEY_ACCOUNT = "account";
const char *const JSON_KEY_DOLLARS = "dollars";
const char *const JSON_KEY_CENTS = "cents";
const char *const JSON_KEY_INIT_BALANCE = "initial_balance";
const char *const JSON_KEY_DEPOSIT = "deposit";
const char *const JSON_KEY_WITHDRAW = "withdraw";
const char *const JSON_KEY_BALANCE = "balance";

const int NUM_DEPOSIT_JSON_KEYS = 4;
const int NUM_WITHDRAW_JSON_KEYS = 4;
const int NUM_NEW_ACCOUNT_JSON_KEYS = 4;
const int NUM_CHECK_BALANCE_JSON_KEYS = 4;
const int NUM_BANK_JSON_KEYS = 4;

const int ERROR_INVALID_ARGUMENTS = 255;
const int ERROR_BANK_AUTH_FILE_EXIST = 255;
const int ERROR_ATM_INVALID_AUTH_FILE = 255;
const int ERROR_ATM_CARD_FILE_EXIST = 255;
const int ERROR_ATM_INVALID_CARD_FILE = 255;
const int ERROR_ATM_FAILED_CONNECT = 63;
const int ERROR_PROTOCOL = 63;
const int ERROR_INVALID_STATE = 255;
const int ERROR_UNKNOWN = 255;

const char *const PROTOCOL_ERR_STR = "protocol_error";
const char *const CREATED_STR = "created";

}
}

#endif //IMPENNETRABLES_CONFIG_H
