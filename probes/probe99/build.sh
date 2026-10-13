#!/bin/bash
set -e
SDK=/mnt/c/Users/rocks/AppData/Local/kex/cache/scratch/ps5/sdk_v043/ps5-payload-sdk
cd /mnt/c/Users/rocks/HV-RE/probes/probe99
$SDK/bin/prospero-clang -Wall -g -I. -c -o trigger.o trigger.c
$SDK/bin/prospero-clang -Wall -g -I. -c -o ap_launch.o ap_launch.S
$SDK/bin/prospero-clang -o trigger.elf trigger.o ap_launch.o
echo "BUILD-OK"
ls -la trigger.elf trigger.o ap_launch.o
