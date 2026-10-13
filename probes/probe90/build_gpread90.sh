#!/bin/bash
set -e
SDK=/mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/sdk_v043/ps5-payload-sdk
cd /mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/probe90
$SDK/bin/prospero-clang -Wall -g -I. -c -o main3.o main3.c
$SDK/bin/prospero-clang -o gpread90.elf main3.o
echo "BUILD-OK"
ls -la gpread90.elf main3.o
