#!/bin/sh

CC=${CC:=cc}
CCOPT="-Wall -W -O2"

$CC gentables.c -o gentables $CCOPT
./gentables > src/tables.c
./gentables h > src/tables.h
echo Tables generated!
