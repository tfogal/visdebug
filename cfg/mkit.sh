#!/bin/sh

function error {
  echo "$@"
  exit 1
}

if test -z "$1" ; then
  error "need arg: program name."
fi
../cfg/printcfg ${1} -dot > ${1}.dot || exit 1
xs dot -Tpng ${1}.dot -o ${1}.png || exit 1
