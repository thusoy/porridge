#!/bin/sh

./venv/bin/py.test \
    --cov porridge \
    --cov-report html:htmlcov \
    --cov-config .coveragerc \
    tests/
