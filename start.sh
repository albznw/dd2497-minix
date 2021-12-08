#!/bin/bash

echo "Starting Minix..."
sudo chmod 777 minix_x86.img
qemu-system-i386 -L . -m 256M -drive file=minix_x86.img,if=ide,format=raw -netdev user,id=mynet0 -device e1000,netdev=mynet0 -serial stdio -curses
