#!/usr/bin/env bash

echo "[+] Starting activity..."

echo "[+] Running some commands (execve)..."
ls /tmp > /dev/null
whoami > /dev/null
uname -a > /dev/null

echo "[+] Reading some config files (openat)..."
cat /etc/hostname > /dev/null
cat /etc/os-release > /dev/null
cat /etc/passwd | head -n 3 > /dev/null

echo "[+] Creating and opening a temp file..."
echo "Hello world" > /tmp/testfile.txt
cat /tmp/testfile.txt > /dev/null
rm /tmp/testfile.txt

echo "[+] Activity done."
