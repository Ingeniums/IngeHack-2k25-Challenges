#!/bin/bash

gcc -s -Wl,-z,now src/main.c -o out -lseccomp