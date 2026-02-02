#!/bin/sh

# This script is executed inside the VM by the Nyx fuzzer

set -eu

# Run the LND fuzzing harness
export SMITE_NYX=1
export PATH=$PATH:/usr/local/bin
/lnd-scenario > /init.log 2>&1
