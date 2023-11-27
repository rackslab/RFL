#!/bin/bash

function install {
    PKG=$1
    if [ -z $EDITABLE ]; then
    	pip install src/${PKG}
    else
    	pip install -e src/${PKG}
    fi
}

# First install core package as it is a dependency for other packages.
install "core"

for PKG in $(ls -1 src); do
    if [ ${PKG} != "core" ]; then
        install ${PKG}
    fi
done
