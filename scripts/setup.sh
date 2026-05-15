#!/bin/bash

python -m venv env
source env/bin/activate

pip install -r requirements.txt

mkdir -p brain/graph/nodes
mkdir -p brain/memory
