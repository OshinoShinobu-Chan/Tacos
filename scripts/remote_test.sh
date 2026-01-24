#!/bin/bash
set -euxo pipefail

tar -czf - ./src | python3 ./scripts/simple_client.py lab1 -