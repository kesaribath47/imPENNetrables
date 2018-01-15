#!/usr/bin/env python

__author__ = "Hung Nguyen"

import select
import subprocess
import threading
import time


class Bank:
    BANK_PATH = '../../bin/bank'

    class BankThread(threading.Thread):
        def __init__(self, path, port, auth):
            self.path = path
            self.port = port
            self.auth = auth
            self.bank = None
            threading.Thread.__init__(self)

        def run(self):
            command = self.path + ' ' + '-p ' + str(self.port) + ' -s ' + self.auth
            self.bank = subprocess.Popen(command.split(),
                                         shell=False,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         bufsize=1)
            self.bank.wait()

        def terminate(self):
            self.bank.terminate()

    def __init__(self, port, auth):
            self.thread = None
            self.port = port
            self.auth = auth

    def start(self):
        self.thread = self.BankThread(self.BANK_PATH, self.port, self.auth)
        self.thread.start()
        time.sleep(1)

    def stop(self):
        self.thread.terminate()

    def read_line_stdout(self):
        poll_stdout = select.poll()
        poll_stdout.register(self.thread.bank.stdout, select.POLLIN)
        poll_result = poll_stdout.poll(0)
        if poll_result:
            return self.thread.bank.stdout.readline().decode('UTF-8').rstrip()
        else:
            return ''

    def read_line_stderr(self):
        poll_stderr = select.poll()
        poll_stderr.register(self.thread.bank.stderr, select.POLLIN)
        poll_result = poll_stderr.poll(0)
        if poll_result:
            return self.thread.bank.stderr.readline().decode('UTF-8').rstrip()
        else:
            return ''
