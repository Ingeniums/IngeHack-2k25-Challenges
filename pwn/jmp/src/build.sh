#!/bin/bash


gcc -Wl,-z,relro,-z,now main.c -o out -lcapstone