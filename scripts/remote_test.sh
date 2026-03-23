#!/bin/bash
set -euxo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <lab1 | lab2 | lab3>"
    exit 1
fi

tar -czf - ./src | python3 ./scripts/simple_client.py $1 -