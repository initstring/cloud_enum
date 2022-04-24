#!/bin/sh

echo Packaging...
python3 -m pip install build
python3 -m build

echo Installing...
pip install dist/*.whl

echo Uninstalling...
pip uninstall cloud_enum -y
