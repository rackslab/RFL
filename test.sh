#!/bin/bash

function test {
    PKG=$1
    python3 -m unittest discover -v src/${PKG}/rfl
}

for PKG in $(ls -1 src); do
  test ${PKG}
done
