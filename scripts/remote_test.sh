#!/bin/bash

server_address=$SERVER

tar -czf - ./src | python3 ./scripts/simple_client.py lab1 -