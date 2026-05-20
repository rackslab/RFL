#!/bin/bash

: ${PIP:="pip"}

# Some platforms ship pip/setuptools without full PEP 517 support for pyproject.toml.
# When PEP517_SETUP_WRAPPER is set, copy the setup.py script from RFL.build into each
# package so pip can build and install them on these older toolchains.
function pep517_setup_wrappers {
    SETUP_SCRIPT="src/build/rfl/build/scripts/setup"
    for PKG in $(ls -1 src); do
        cp "${SETUP_SCRIPT}" "src/${PKG}/setup.py"
    done
}

if [ -n "$PEP517_SETUP_WRAPPER" ]; then
    pep517_setup_wrappers
fi

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
