#!/bin/bash
set -e
SDK=/mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/sdk_v043/ps5-payload-sdk
cd /mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/probe93
$SDK/bin/prospero-clang -Wall -g -I. -c -o a53verify.o a53verify.c
$SDK/bin/prospero-clang -o a53verify.elf a53verify.o
echo "BUILD-OK"
ls -la a53verify.elf
