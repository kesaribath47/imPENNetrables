#!/usr/bin/python

from __future__ import print_function
from multiprocessing import Process, Queue
from Queue import Empty
import json
import base64
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ATM_ORACLE = './oracle_atm'
BANK_ORACLE = './oracle_bank'

ARG_FILE = '/tmp/args'

ATM_USER = 'client'
BANK_USER = 'server'
MITM_USER = 'ubuntu'


def failed( s):
	print( s, file=sys.stderr)
	exit(1)

def settings( port):
	return {
		'ip': '127.0.0.1',
		'port': port
	}

def checkExists( f):
	if not os.path.isfile( f):
		failed( "file not found: %s" % f)

def runBreak( testDir, targetDir):
	# Give warning if description.txt not found. 
	checkExists( testDir + "/description.txt")


	testFileName = testDir + "/test.json"
	checkExists( testFileName)
	
	try:
		testFile = open( testFileName, 'r')
	except IOError:
		failed( "Could not open file: %s" % testFileName)
	tmp = testFile.read()
	testFile.close()


	try:
		testFile = json.loads( tmp)

		typ = testFile['type']
		inputs = testFile['inputs'] if 'inputs' in testFile else None
	except:
		failed( "Invalid json break file")
	
	atm = os.path.abspath( targetDir + "/atm")
	bank = os.path.abspath( targetDir + "/bank")
	mitm = os.path.abspath( testDir + "/mitm")

	atmOracle = os.path.abspath( ATM_ORACLE)
	bankOracle = os.path.abspath( BANK_ORACLE)

	# Check that all of them exist. 
	checkExists( atm)
	checkExists( bank)
	checkExists( atmOracle)
	checkExists( bankOracle)
	if typ == "integrity" or typ == "confidentiality":
		checkExists( mitm)

	arg = {
		'type': typ,
		'tests': inputs,
		'atm': atm,
		'bank': bank,
		'bank_settings': settings(3700),
		'oracle_atm': atmOracle,
		'oracle_bank': bankOracle,
		'oracle_bank_settings': settings(3600),
		'atm_user': ATM_USER, 
		'bank_user': BANK_USER,
		'command_settings': settings(5000),
		'mitm': mitm,
		'mitm_settings': settings(4000),
		'mitm_user': MITM_USER
	}

	arg = base64.b64encode( json.dumps( arg))

	argF = open(ARG_FILE, 'w')
	argF.write(arg)
	argF.close()

	args = ['./grader',ARG_FILE]


	p = subprocess.Popen( args) # , cwd = d)
	try:
		p.wait()
	except:
		pass

	# Kill mitm and banks in case.
	os.system( "sudo killall bank oracle_bank mitm python2 2> /dev/null")


# Main
def main():
	if len( sys.argv) < 3:
		print("usage: run_test <test_dir> <target_dir>")
		exit(1)
	
	testDir = sys.argv[1]
	targetDir = sys.argv[2]

	runBreak( testDir, targetDir)

main()
