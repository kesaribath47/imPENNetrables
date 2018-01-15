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


def log(m):
    print(m, file=sys.stderr)


def mitm(buff, direction, shared):
    hb = "".join("{:02x}".format(c) for c in buff)

    if direction == CLIENT2SERVER:
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
        print("started")
        sys.stdout.flush()
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
    do_proxy_main(args.p, args.s, args.q)
