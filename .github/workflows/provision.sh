#!/bin/bash

set -ex

# Install dependencies
sudo apt-get install -y \
  libunwind-dev # Needed by `ic-canister-sandbox-backend-lib`