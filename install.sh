#!/bin/bash

: ${PIP:="pip"}

function install {
    PKG=$1
    PIP_ARGS=()
    if [ -n "$NODEPS" ]; then
        PIP_ARGS+=(--no-deps)
    fi
    ${PIP} install "${PIP_ARGS[@]}" ${EDITABLE:+-e} "src/${PKG}"
}

# First install core package as it is a dependency for other packages.
install "core"

for PKG in $(ls -1 src); do
    if [ ${PKG} != "core" ]; then
        install ${PKG}
    fi
done
