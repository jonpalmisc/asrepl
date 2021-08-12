#!/usr/bin/env bash

DIST_DIR=./build/webdist

rm -rf ${DIST_DIR}
mkdir ${DIST_DIR}
cp ./build/index.html ${DIST_DIR}
cp ./build/asrepl.css ${DIST_DIR}
cp ./build/asrepl-web.js ${DIST_DIR}
cp ./build/asrepl-web.wasm ${DIST_DIR}

az storage blob upload-batch -s ${DIST_DIR} -d "\$web" --account-name asrepl
