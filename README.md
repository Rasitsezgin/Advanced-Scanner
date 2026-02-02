# Advanced-Scanner


# Basit tarama
sudo ./advanced_scanner.sh -t example.com

# Hızlı tarama
sudo ./advanced_scanner.sh -t 192.168.1.1 -l quick

# Detaylı tarama
sudo ./advanced_scanner.sh -t target.com -l deep

# Web sunucu taraması
sudo ./advanced_scanner.sh -t webapp.com -l normal --skip-slow

# Network denetimi
sudo ./advanced_scanner.sh -t 10.0.0.0/24 -l deep -T 15

# Tam penetrasyon testi
sudo ./advanced_scanner.sh -t target.com -l extreme -o /root/pentest
