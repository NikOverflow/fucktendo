#!/bin/sh
scriptPath="$(realpath "$(dirname $0)")"
cd "$scriptPath/../"

python -m venv .venv
. .venv/bin/activate
pip install -e pyfucktendo
