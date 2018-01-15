#!/usr/bin/env python

__author__ = "Hung Nguyen"

import base64
from glob import glob
import json
import os
import random
import traceback
import uuid

from bank import *
from atm import *

TEST_CASES = ['001', '002', '003', '004', '005', '006', '007']
TEST_CASE_PREFIX = 'test_cases/'
TEST_CASE_SUFFIX = '.txt'
BANK_ADDRESS = '127.0.0.1'


class Tester:
    def __init__(self):
        pass

    @staticmethod
    def is_correct_output(output, expected_output):
        try:
            json_output = json.loads(output)
            for key, value in expected_output.items():
                if json_output.get(key) is None or json_output[key] != value:
                    return False
        except ValueError:
            # traceback.print_exc()
            return False

        return True

    @staticmethod
    def run(input, output, mute):
        if len(input) != len(output):
            print('Invalid input files!')
            return

        failed_commands = []
        address = BANK_ADDRESS
        port = random.randint(1024, 65535)
        auth = 'bank-' + str(uuid.uuid4()) + '.auth'

        print('BANK will run at ' + address + ' on port ' + str(port) + ' with auth file ' + auth)

        # Run BANK
        bank = Bank(port, auth)
        bank.start()
        try:
            if bank.read_line_stdout() != 'created':
                print('BANK failed to initialize!')
                return
            else:
                print('BANK started!')
                while True:
                    message = bank.read_line_stderr()
                    if not message:
                        break

            for i in range(len(input)):
                arguments = input[i]['input']
                if input[i].get('base64') is not None and input[i]['base64']:
                    arguments = [base64.b64decode(e).decode('UTF-8') for e in arguments]
                arguments = [e.replace('%IP%', address) for e in arguments]
                arguments = [e.replace('%PORT%', str(port)) for e in arguments]
                if '-s' not in arguments:
                    arguments.append('-s')
                    arguments.append(auth)
                if not mute:
                    print('\n++ Command #' + str(i) + ' ++')
                    print('- Input : ' + str(input[i]))
                    print('- Output: ' + str(output[i]))

                atm = Atm(arguments)
                rc = atm.run()
                atm_stdout = atm.read_stdout()
                atm_failed = False
                bank_failed = False

                if rc != output[i]['atm']['exit']:
                    atm_failed = True
                    if not mute:
                        print('<!!> Got invalid atm exit code: ' + str(rc))

                if ((output[i]['atm'].get('output') is None and atm_stdout)
                        or (output[i]['atm'].get('output') is not None
                            and not Tester.is_correct_output(atm_stdout, output[i]['atm']['output']))):
                    atm_failed = True
                    if not mute:
                        print('<!!> Got invalid atm output: ' + atm_stdout)

                if atm_failed:
                    atm_stderr = atm.read_stderr()
                    if not mute:
                        print('@@ ATM STDERR @@\n' + atm_stderr)

                time.sleep(0.2)
                bank_stdout = bank.read_line_stdout()

                if ((output[i]['bank'].get('output') is None and bank_stdout)
                        or (output[i]['bank'].get('output') is not None
                            and not Tester.is_correct_output(bank_stdout, output[i]['bank']['output']))):
                    bank_failed = True
                    if not mute:
                        print('<!!> Got invalid bank output: ' + bank_stdout)
                        print('@@ BANK STDERR @@')
                    while True:
                        message = bank.read_line_stderr()
                        if not message:
                            break
                        else:
                            if not mute:
                                print(message)

                # flush bank stdout
                while True:
                    message = bank.read_line_stdout()
                    if not message:
                        break

                if atm_failed or bank_failed:
                    failed_commands.append(i)
                    if not mute:
                        print('<!!> TEST COMMAND #' + str(i) + ' FAILED!')
                else:
                    if not mute:
                        print('<!!> TEST COMMAND #' + str(i) + ' PASSED!')
        except Exception as e:
            print("Unexpected error: ", e)
            # traceback.print_exc()
        finally:
            bank.stop()
            print('\nBANK stopped!')
        return failed_commands


if __name__ == "__main__":
    failed_cases = []
    for test in TEST_CASES:
        print('*** RUNNING TEST CASE ' + test + ' ***')
        try:
            data = json.load(open(TEST_CASE_PREFIX + test + TEST_CASE_SUFFIX))
            mute = data.get('mute') is not None and data['mute']
            print('Description: ' + data['description'] + '\n')

            tester = Tester()
            failed_cases.append(tester.run(data["input"], data["output"], mute))

        except Exception as e:
            print("Unexpected error: ", e)
            traceback.print_exc()
    print('\n*** FAILED SUMMARY ***')
    for i in range(len(failed_cases)):
        print('Test #' + str(i) + ': ' + str(failed_cases[i]))
    [os.remove(f) for f in glob('*.auth')]
    [os.remove(f) for f in glob('*.card')]
