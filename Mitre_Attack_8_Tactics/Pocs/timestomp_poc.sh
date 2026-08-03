#!/bin/bash
#T1070.006 - Timestomp PoC (Linux)

echo "Timestomp islemi basliyor..."

#Zararliyi simule eden yeni bir dosya olustur
PAYLOAD="/tmp/zayotem_payload.elf"
echo "Malware payload icerigi" > "$PAYLOAD"

echo "Yeni payload olusturuldu. Orijinal zaman damgalari:"
stat "$PAYLOAD" | grep -E "Access:|Modify:|Change:"

echo "---------------------------------------------------"

#Kurban dosya
REF_FILE="/bin/bash"
echo "[*] Referans dosya ($REF_FILE) zaman damgalari kopyalaniyor..."

#Timestomp
touch -r "$REF_FILE" "$PAYLOAD"

echo "[+] Timestomp basarili! Payload'un yeni zaman damgalari:"
stat "$PAYLOAD" | grep -E "Access:|Modify:|Change:"