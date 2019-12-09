#! /bin/bash
awk '{print \$4}' /proc/$1/psinfo >> temp.txt
