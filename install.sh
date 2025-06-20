#!/bin/bash

: ${PIP:="pip"}

function install {
    PKG=$1
    if [ -z $EDITABLE ]; then
    	${PIP} install src/${PKG}
    else
    	${PIP} install -e src/${PKG}
    fi
}

# First install core package as it is a dependency for other packages.
install "core"

for PKG in $(ls -1 src); do
    if [ ${PKG} != "core" ]; then
        install ${PKG}
    fi
done
