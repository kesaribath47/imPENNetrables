#!/bin/bash
find . -name "*.json" -exec bash -c './run_test.py {}' \;
