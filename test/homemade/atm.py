#!/usr/bin/env python

__author__ = "Hung Nguyen"

import threading
import subprocess


class Atm:
    ATM_PATH = '../../bin/atm'

    class AtmThread(threading.Thread):
        def __init__(self, path, args):
            self.atm = None
            self.path = path
            self.args = args
            self.stdout = None
            self.stderr = None
            self.rc = 0
            threading.Thread.__init__(self)

        def run(self):
            command = self.path + ' ' + ' '.join(self.args)
            self.atm = subprocess.Popen(command.split(),
                                        shell=False,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        bufsize=1)
            self.stdout, self.stderr = self.atm.communicate()
            self.rc = self.atm.returncode

        def terminate(self):
            self.atm.terminate()

    def __init__(self, args):
        self.atm = None
        self.args = args

    def run(self):
        self.atm = self.AtmThread(self.ATM_PATH, self.args)
        self.atm.start()
        self.atm.join()
        return self.atm.rc

    def read_stdout(self):
        return self.atm.stdout.decode('UTF-8').rstrip()

    def read_stderr(self):
        return self.atm.stderr.decode('UTF-8').rstrip()
