#!/bin/sh

set -e

BINARY=${1}
OUTFILE=${2}

shift 2

rm -f "${OUTFILE}"
"${BINARY}" "${OUTFILE}" "${@}"
hexdump -b "${OUTFILE}"
