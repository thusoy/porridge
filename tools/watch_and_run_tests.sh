#!/bin/sh

TEST_COMMAND="./test --exitfirst --failed-first"

$TEST_COMMAND

./venv/bin/watchmedo shell-command \
    --patterns="*.py" \
    --recursive \
    --command "$TEST_COMMAND" \
    porridge/ tests/
