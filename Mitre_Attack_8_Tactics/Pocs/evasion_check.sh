#!/bin/bash
#T1613 - Container and Resource Discovery PoC (Linux)

echo "Anti-Analysis ve Discovery testleri basliyor..."

#Container kontrolü
if [ -f /.dockerenv ]; then
    echo ".dockerenv dosyasi bulundu. Container ortamindayiz."
    is_sandbox=1
elif grep -qE "(docker|lxc|kubepods)" /proc/1/cgroup 2>/dev/null; then
    echo "/proc/1/cgroup icinde container izleri bulundu."
    is_sandbox=1
else
    echo "Container' da oldugumuza dair bir isaret yok ortam temiz."
    is_sandbox=0
fi

#Donanım özelliklerinin testi
CPU_CORES=$(nproc 2>/dev/null)
RAM_TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
RAM_TOTAL_GB=$((RAM_TOTAL_KB / 1024 / 1024))

echo "Donanim Profili: CPU Cores = $CPU_CORES | RAM = ${RAM_TOTAL_GB}GB"

if [ "$CPU_CORES" -lt 2 ] || [ "$RAM_TOTAL_GB" -lt 2 ]; then
    echo "Donanim kaynaklari supheli sandbox'ta olabiliriz."
    is_sandbox=1
fi

#Karar anı
echo "---------------------------------------------------"
if [ "$is_sandbox" -eq 1 ]; then
    echo "Payload calistirilmicak analiz ortami tespit edildi."
    exit 1
else
    echo "Payload calistiriliyor ortam dogrulandi."
    #Asıl zararlı faaliyetleri burada başlar
fi