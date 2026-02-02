#!/bin/bash

#############################################################################
# Advanced Security Scanner v2.0
# Profesyonel Penetrasyon Testi ve Güvenlik Analiz Aracı
# Yazar: Security Team
# Lisans: MIT
#############################################################################

# Renkli çıktı için ANSI kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Global değişkenler
VERSION="2.0"
TARGET=""
OUTPUT_DIR=""
SCAN_LEVEL="normal"
THREADS=10
SKIP_SLOW=false
VERBOSE=false
REPORT_FORMAT="all"
START_TIME=$(date +%s)

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗   ║
║   ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝   ║
║   ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║        ║
║   ██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║        ║
║   ██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗   ║
║   ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ║
║                                                           ║
║       SECURITY SCANNER & PENETRATION TOOLKIT              ║
║                   Version 2.0                             ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Log fonksiyonları
log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$OUTPUT_DIR/scan.log"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$OUTPUT_DIR/scan.log"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$OUTPUT_DIR/scan.log"
}

log_info() {
    echo -e "${BLUE}[i]${NC} $1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$OUTPUT_DIR/scan.log"
}

log_step() {
    echo -e "${PURPLE}[▶]${NC} ${BOLD}$1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [STEP] $1" >> "$OUTPUT_DIR/scan.log"
}

# Yardım menüsü
show_help() {
    cat << EOF
${BOLD}Kullanım:${NC}
    $0 -t <hedef> [seçenekler]

${BOLD}Zorunlu Parametreler:${NC}
    -t, --target <hedef>        Hedef IP adresi veya domain

${BOLD}Opsiyonel Parametreler:${NC}
    -l, --level <seviye>        Tarama seviyesi (quick/normal/deep/extreme)
                                Varsayılan: normal
    -o, --output <dizin>        Çıktı dizini
    -T, --threads <sayı>        Thread sayısı (1-20)
                                Varsayılan: 10
    -f, --format <format>       Rapor formatı (txt/xml/html/all)
                                Varsayılan: all
    --skip-slow                 Yavaş taramaları atla
    -v, --verbose               Detaylı çıktı
    -h, --help                  Bu yardım mesajını göster

${BOLD}Tarama Seviyeleri:${NC}
    quick   - Hızlı port keşfi ve temel servis tespiti
    normal  - Standart güvenlik taraması (önerilen)
    deep    - Detaylı zafiyet analizi ve exploit tespiti
    extreme - Tüm portlar, tüm scriptler (çok uzun sürer)

${BOLD}Örnekler:${NC}
    $0 -t 192.168.1.1
    $0 -t example.com -l deep -T 15
    $0 -t 10.0.0.1 --skip-slow -v
    $0 -t target.com -l extreme -o /tmp/scan_results

${BOLD}Not:${NC}
    - Root yetkisi gerektirir (sudo)
    - Sadece izniniz olan sistemlerde kullanın
    - Yasal sorumluluk kullanıcıya aittir
EOF
}

# Gerekli araçları kontrol et
check_requirements() {
    log_step "Gerekli araçlar kontrol ediliyor..."
    
    local required_tools=("nmap" "nc" "dig" "whois")
    local optional_tools=("nikto" "sqlmap" "hydra" "dirb" "gobuster" "wpscan" "sslyze" "testssl.sh")
    local missing_required=()
    local missing_optional=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_required+=($tool)
        fi
    done
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_optional+=($tool)
        fi
    done
    
    if [ ${#missing_required[@]} -gt 0 ]; then
        log_error "Eksik zorunlu araçlar: ${missing_required[*]}"
        log_info "Kurulum: sudo apt install ${missing_required[*]}"
        exit 1
    fi
    
    if [ ${#missing_optional[@]} -gt 0 ]; then
        log_warning "Eksik opsiyonel araçlar: ${missing_optional[*]}"
        log_info "Bazı özellikler sınırlı olacak"
    fi
    
    log_success "Araç kontrolü tamamlandı"
}

# Hedef bilgilerini topla
gather_target_info() {
    log_step "Hedef hakkında bilgi toplama başlatılıyor..."
    
    mkdir -p "$OUTPUT_DIR/recon"
    
    # DNS bilgileri
    log_info "DNS kayıtları sorgulanıyor..."
    {
        echo "=== DNS Kayıtları ==="
        dig +short $TARGET A
        dig +short $TARGET AAAA
        dig +short $TARGET MX
        dig +short $TARGET TXT
        dig +short $TARGET NS
    } > "$OUTPUT_DIR/recon/dns_records.txt" 2>&1
    
    # WHOIS bilgisi
    log_info "WHOIS bilgisi alınıyor..."
    whois $TARGET > "$OUTPUT_DIR/recon/whois.txt" 2>&1
    
    # Reverse DNS
    log_info "Reverse DNS kontrolü..."
    host $TARGET > "$OUTPUT_DIR/recon/reverse_dns.txt" 2>&1
    
    # Subdomain enumeration (pasif)
    if command -v subfinder &> /dev/null; then
        log_info "Subdomain keşfi yapılıyor..."
        subfinder -d $TARGET -silent > "$OUTPUT_DIR/recon/subdomains.txt" 2>&1
    fi
    
    log_success "Bilgi toplama tamamlandı"
}

# Port taraması - Quick
scan_ports_quick() {
    log_step "Hızlı port taraması yapılıyor..."
    
    nmap -T4 -F --open -Pn --min-rate=1000 \
        -oN "$OUTPUT_DIR/01_quick_scan.txt" \
        -oX "$OUTPUT_DIR/01_quick_scan.xml" \
        $TARGET
    
    log_success "Hızlı tarama tamamlandı"
}

# Port taraması - Full
scan_ports_full() {
    log_step "Tüm portlar taranıyor (65535 port)..."
    
    nmap -p- -T4 --open -Pn --min-rate=5000 \
        -oN "$OUTPUT_DIR/02_full_port_scan.txt" \
        -oX "$OUTPUT_DIR/02_full_port_scan.xml" \
        $TARGET
    
    log_success "Tam port taraması tamamlandı"
}

# Servis ve versiyon tespiti
scan_service_version() {
    log_step "Servis versiyonları tespit ediliyor..."
    
    nmap -sV -sC --version-intensity 9 -Pn \
        -oN "$OUTPUT_DIR/03_service_version.txt" \
        -oX "$OUTPUT_DIR/03_service_version.xml" \
        $TARGET
    
    log_success "Servis tespiti tamamlandı"
}

# İşletim sistemi tespiti
scan_os_detection() {
    log_step "İşletim sistemi tespiti yapılıyor..."
    
    nmap -O --osscan-guess --fuzzy -Pn \
        -oN "$OUTPUT_DIR/04_os_detection.txt" \
        -oX "$OUTPUT_DIR/04_os_detection.xml" \
        $TARGET
    
    log_success "OS tespiti tamamlandı"
}

# UDP taraması
scan_udp() {
    if [ "$SKIP_SLOW" = true ]; then
        log_warning "UDP taraması atlandı (--skip-slow)"
        return
    fi
    
    log_step "UDP port taraması yapılıyor..."
    
    nmap -sU --top-ports 1000 -T4 -Pn \
        -oN "$OUTPUT_DIR/05_udp_scan.txt" \
        -oX "$OUTPUT_DIR/05_udp_scan.xml" \
        $TARGET
    
    log_success "UDP taraması tamamlandı"
}

# Zafiyet taraması - Genel
scan_vulnerabilities() {
    log_step "Güvenlik açıkları taranıyor..."
    
    nmap --script vuln -sV -Pn \
        -oN "$OUTPUT_DIR/06_vulnerability_scan.txt" \
        -oX "$OUTPUT_DIR/06_vulnerability_scan.xml" \
        $TARGET
    
    log_success "Zafiyet taraması tamamlandı"
}

# SSL/TLS taraması
scan_ssl_tls() {
    log_step "SSL/TLS güvenlik analizi yapılıyor..."
    
    # Nmap ile SSL tarama
    nmap -p 443,8443,8080 --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection \
        -oN "$OUTPUT_DIR/07_ssl_nmap.txt" \
        -oX "$OUTPUT_DIR/07_ssl_nmap.xml" \
        $TARGET 2>&1
    
    # testssl.sh varsa kullan
    if command -v testssl.sh &> /dev/null; then
        log_info "testssl.sh ile detaylı SSL analizi..."
        testssl.sh --fast $TARGET > "$OUTPUT_DIR/07_ssl_testssl.txt" 2>&1
    fi
    
    log_success "SSL/TLS taraması tamamlandı"
}

# Web uygulama taraması
scan_web_application() {
    log_step "Web uygulaması analiz ediliyor..."
    
    # Nmap web scriptleri
    nmap -p 80,443,8080,8443 --script http-enum,http-headers,http-methods,http-title,http-server-header,http-robots.txt,http-sitemap-generator,http-git,http-svn-enum,http-backup-finder \
        -oN "$OUTPUT_DIR/08_web_nmap.txt" \
        -oX "$OUTPUT_DIR/08_web_nmap.xml" \
        $TARGET 2>&1
    
    # Nikto taraması
    if command -v nikto &> /dev/null; then
        log_info "Nikto web zafiyet taraması..."
        nikto -h $TARGET -output "$OUTPUT_DIR/08_web_nikto.txt" 2>&1
    fi
    
    # Directory brute force
    if command -v gobuster &> /dev/null && [ -f /usr/share/wordlists/dirb/common.txt ]; then
        log_info "Directory brute force saldırısı..."
        gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/08_web_gobuster.txt" -q 2>&1
    elif command -v dirb &> /dev/null; then
        log_info "Directory brute force (dirb)..."
        dirb http://$TARGET -o "$OUTPUT_DIR/08_web_dirb.txt" -S -r 2>&1
    fi
    
    # WordPress tespiti
    if command -v wpscan &> /dev/null; then
        log_info "WordPress zafiyet taraması..."
        wpscan --url http://$TARGET --enumerate vp,vt,u --no-banner -o "$OUTPUT_DIR/08_web_wpscan.txt" 2>&1 || true
    fi
    
    log_success "Web taraması tamamlandı"
}

# SMB/CIFS taraması
scan_smb() {
    log_step "SMB/CIFS servisleri analiz ediliyor..."
    
    nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067,smb-double-pulsar-backdoor \
        -oN "$OUTPUT_DIR/09_smb_scan.txt" \
        -oX "$OUTPUT_DIR/09_smb_scan.xml" \
        $TARGET 2>&1
    
    log_success "SMB taraması tamamlandı"
}

# FTP taraması
scan_ftp() {
    log_step "FTP servisi kontrol ediliyor..."
    
    nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 \
        -oN "$OUTPUT_DIR/10_ftp_scan.txt" \
        -oX "$OUTPUT_DIR/10_ftp_scan.xml" \
        $TARGET 2>&1
    
    log_success "FTP taraması tamamlandı"
}

# SSH taraması
scan_ssh() {
    log_step "SSH servisi analiz ediliyor..."
    
    nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1,ssh-brute \
        -oN "$OUTPUT_DIR/11_ssh_scan.txt" \
        -oX "$OUTPUT_DIR/11_ssh_scan.xml" \
        $TARGET 2>&1
    
    log_success "SSH taraması tamamlandı"
}

# Database taraması
scan_databases() {
    log_step "Veritabanı servisleri kontrol ediliyor..."
    
    nmap -p 1433,3306,5432,27017,6379,5984 --script mysql-info,mysql-empty-password,mysql-vuln-cve2012-2122,ms-sql-info,ms-sql-empty-password,pgsql-brute,mongodb-info,redis-info \
        -oN "$OUTPUT_DIR/12_database_scan.txt" \
        -oX "$OUTPUT_DIR/12_database_scan.xml" \
        $TARGET 2>&1
    
    # SQL Injection testi (sqlmap)
    if command -v sqlmap &> /dev/null && [ "$SCAN_LEVEL" = "extreme" ]; then
        log_info "SQL Injection testi (sqlmap)..."
        sqlmap -u "http://$TARGET" --batch --crawl=2 --level=1 --risk=1 -o "$OUTPUT_DIR/12_sqlmap.txt" 2>&1 || true
    fi
    
    log_success "Database taraması tamamlandı"
}

# Mail servisleri taraması
scan_mail_services() {
    log_step "Mail servisleri kontrol ediliyor..."
    
    nmap -p 25,110,143,465,587,993,995 --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-open-relay,pop3-capabilities,imap-capabilities \
        -oN "$OUTPUT_DIR/13_mail_scan.txt" \
        -oX "$OUTPUT_DIR/13_mail_scan.xml" \
        $TARGET 2>&1
    
    log_success "Mail servisleri taraması tamamlandı"
}

# DNS taraması
scan_dns() {
    log_step "DNS servisi analiz ediliyor..."
    
    nmap -p 53 --script dns-zone-transfer,dns-recursion,dns-cache-snoop,dns-nsid \
        -oN "$OUTPUT_DIR/14_dns_scan.txt" \
        -oX "$OUTPUT_DIR/14_dns_scan.xml" \
        $TARGET 2>&1
    
    log_success "DNS taraması tamamlandı"
}

# Firewall/IDS tespiti
scan_firewall_ids() {
    log_step "Firewall/IDS tespiti yapılıyor..."
    
    nmap -sA -T4 -p- --max-retries 1 \
        -oN "$OUTPUT_DIR/15_firewall_detection.txt" \
        -oX "$OUTPUT_DIR/15_firewall_detection.xml" \
        $TARGET 2>&1
    
    log_success "Firewall tespiti tamamlandı"
}

# Brute force saldırıları
scan_brute_force() {
    if [ "$SCAN_LEVEL" != "extreme" ]; then
        log_warning "Brute force atlandı (extreme modda çalışır)"
        return
    fi
    
    log_step "Brute force saldırıları deneniyor..."
    
    if command -v hydra &> /dev/null; then
        # SSH brute force (sadece birkaç yaygın şifre)
        log_info "SSH brute force (limited)..."
        echo -e "admin\nroot\nuser" > /tmp/users.txt
        echo -e "password\n123456\nadmin" > /tmp/passwords.txt
        hydra -L /tmp/users.txt -P /tmp/passwords.txt ssh://$TARGET -t 4 -o "$OUTPUT_DIR/16_ssh_brute.txt" 2>&1 || true
        rm -f /tmp/users.txt /tmp/passwords.txt
    fi
    
    log_success "Brute force testleri tamamlandı"
}

# Exploit taraması
scan_exploits() {
    log_step "Exploit ve zafiyet modülleri test ediliyor..."
    
    # Metasploit modülleri için NSE scriptleri
    nmap --script exploit,intrusive -sV -Pn \
        -oN "$OUTPUT_DIR/17_exploit_scan.txt" \
        -oX "$OUTPUT_DIR/17_exploit_scan.xml" \
        $TARGET 2>&1
    
    log_success "Exploit taraması tamamlandı"
}

# Network analizi
scan_network_analysis() {
    log_step "Network analizi yapılıyor..."
    
    # Traceroute
    nmap --traceroute -Pn \
        -oN "$OUTPUT_DIR/18_traceroute.txt" \
        -oX "$OUTPUT_DIR/18_traceroute.xml" \
        $TARGET 2>&1
    
    # TTL ve Hops analizi
    hping3 -c 3 -S -p 80 $TARGET > "$OUTPUT_DIR/18_hping3.txt" 2>&1 || true
    
    log_success "Network analizi tamamlandı"
}

# VPN/Tunnel tespiti
scan_vpn_tunnel() {
    log_step "VPN/Tunnel servisleri kontrol ediliyor..."
    
    nmap -p 500,1194,1723,4500 --script ike-version,pptp-version \
        -oN "$OUTPUT_DIR/19_vpn_scan.txt" \
        -oX "$OUTPUT_DIR/19_vpn_scan.xml" \
        $TARGET 2>&1
    
    log_success "VPN taraması tamamlandı"
}

# SNMP taraması
scan_snmp() {
    log_step "SNMP servisi kontrol ediliyor..."
    
    nmap -sU -p 161,162 --script snmp-info,snmp-brute,snmp-processes,snmp-sysdescr \
        -oN "$OUTPUT_DIR/20_snmp_scan.txt" \
        -oX "$OUTPUT_DIR/20_snmp_scan.xml" \
        $TARGET 2>&1
    
    log_success "SNMP taraması tamamlandı"
}

# Özet rapor oluştur
generate_summary_report() {
    log_step "Özet rapor hazırlanıyor..."
    
    local report_file="$OUTPUT_DIR/00_EXECUTIVE_SUMMARY.txt"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    cat > "$report_file" << EOF
╔══════════════════════════════════════════════════════════════════════╗
║                     GÜVENLİK TARAMASI ÖZET RAPORU                   ║
╚══════════════════════════════════════════════════════════════════════╝

TARAMA BİLGİLERİ
────────────────────────────────────────────────────────────────────────
Hedef               : $TARGET
Tarama Seviyesi     : $SCAN_LEVEL
Başlangıç Zamanı    : $(date -d @$START_TIME +'%Y-%m-%d %H:%M:%S')
Bitiş Zamanı        : $(date +'%Y-%m-%d %H:%M:%S')
Toplam Süre         : $((duration / 60)) dakika $((duration % 60)) saniye
Rapor Dizini        : $OUTPUT_DIR

════════════════════════════════════════════════════════════════════════
1. AÇIK PORTLAR VE SERVİSLER
════════════════════════════════════════════════════════════════════════
EOF

    # Açık portları topla
    find "$OUTPUT_DIR" -name "*.txt" -exec grep -h "^[0-9]*/tcp.*open" {} \; 2>/dev/null | sort -u >> "$report_file"
    find "$OUTPUT_DIR" -name "*.txt" -exec grep -h "^[0-9]*/udp.*open" {} \; 2>/dev/null | sort -u >> "$report_file"
    
    cat >> "$report_file" << EOF

════════════════════════════════════════════════════════════════════════
2. TESPİT EDİLEN GÜVENLİK AÇIKLIKLARI
════════════════════════════════════════════════════════════════════════
EOF

    # Güvenlik açıklarını topla
    find "$OUTPUT_DIR" -name "*.txt" -exec grep -Hi "VULNERABLE\|CVE-\|CRITICAL\|HIGH RISK" {} \; 2>/dev/null | sed 's/^/  /' >> "$report_file"
    
    if ! grep -q "VULNERABLE\|CVE-" "$report_file"; then
        echo "  ✓ Kritik güvenlik açığı tespit edilmedi." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

════════════════════════════════════════════════════════════════════════
3. SSL/TLS GÜVENLİK DURUMU
════════════════════════════════════════════════════════════════════════
EOF

    grep -h "SSL\|TLS\|Certificate" "$OUTPUT_DIR"/07_ssl*.txt 2>/dev/null | head -20 | sed 's/^/  /' >> "$report_file" || echo "  SSL/TLS bilgisi bulunamadı" >> "$report_file"
    
    cat >> "$report_file" << EOF

════════════════════════════════════════════════════════════════════════
4. WEB UYGULAMASI GÜVENLİK BULGULARI
════════════════════════════════════════════════════════════════════════
EOF

    grep -h "OSVDB\|vulnerable\|exposure" "$OUTPUT_DIR"/08_web*.txt 2>/dev/null | head -20 | sed 's/^/  /' >> "$report_file" || echo "  Web güvenlik testi yapılmadı" >> "$report_file"
    
    cat >> "$report_file" << EOF

════════════════════════════════════════════════════════════════════════
5. ÖNCELİKLİ GÜVENLİK ÖNERİLERİ
════════════════════════════════════════════════════════════════════════
[YÜKSEK ÖNCELİK]
  • Kritik güvenlik yamalarını hemen uygulayın
  • Gereksiz servisleri kapatın ve güvenlik duvarını yapılandırın
  • Varsayılan şifreleri değiştirin
  • Güncel olmayan yazılımları yükseltin

[ORTA ÖNCELİK]
  • SSL/TLS konfigürasyonunu sıkılaştırın (minimum TLS 1.2)
  • Zayıf şifreleme algoritmalarını devre dışı bırakın
  • Brute force koruması ekleyin (fail2ban vb.)
  • Log yönetimi ve izleme sistemleri kurun

[DÜŞÜK ÖNCELİK]
  • Banner bilgilerini gizleyin
  • Rate limiting uygulayın
  • HSTS, CSP gibi güvenlik başlıklarını ekleyin
  • Düzenli güvenlik taramaları planlayın

════════════════════════════════════════════════════════════════════════
6. DETAYLI RAPOR DOSYALARI
════════════════════════════════════════════════════════════════════════
EOF

    # Oluşturulan dosyaları listele
    find "$OUTPUT_DIR" -type f -name "*.txt" -o -name "*.xml" -o -name "*.html" | sort | while read file; do
        echo "  📄 $(basename "$file")" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF

════════════════════════════════════════════════════════════════════════
YASAL UYARI
════════════════════════════════════════════════════════════════════════
Bu tarama sadece eğitim ve güvenlik denetimi amaçlıdır.
Sadece izniniz olan sistemlerde kullanın.
Yasal sorumluluk tamamen kullanıcıya aittir.

════════════════════════════════════════════════════════════════════════
Rapor oluşturuldu: $(date +'%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════════════
EOF

    log_success "Özet rapor oluşturuldu: $report_file"
}

# HTML rapor oluştur
generate_html_report() {
    if [ "$REPORT_FORMAT" != "html" ] && [ "$REPORT_FORMAT" != "all" ]; then
        return
    fi
    
    log_step "HTML raporu oluşturuluyor..."
    
    # XML dosyalarını HTML'e dönüştür
    if command -v xsltproc &> /dev/null; then
        for xml_file in "$OUTPUT_DIR"/*.xml; do
            if [ -f "$xml_file" ]; then
                html_file="${xml_file%.xml}.html"
                xsltproc "$xml_file" -o "$html_file" 2>/dev/null || true
            fi
        done
    fi
    
    log_success "HTML raporları oluşturuldu"
}

# Ana tarama fonksiyonu
run_scan() {
    case $SCAN_LEVEL in
        "quick")
            scan_ports_quick
            scan_service_version
            scan_os_detection
            ;;
        "normal")
            scan_ports_quick
            scan_service_version
            scan_os_detection
            scan_vulnerabilities
            scan_ssl_tls
            scan_web_application
            scan_smb
            scan_ftp
            scan_ssh
            ;;
        "deep")
            scan_ports_full
            scan_service_version
            scan_os_detection
            scan_udp
            scan_vulnerabilities
            scan_ssl_tls
            scan_web_application
            scan_smb
            scan_ftp
            scan_ssh
            scan_databases
            scan_mail_services
            scan_dns
            scan_firewall_ids
            scan_vpn_tunnel
            scan_snmp
            ;;
        "extreme")
            scan_ports_full
            scan_service_version
            scan_os_detection
            scan_udp
            scan_vulnerabilities
            scan_ssl_tls
            scan_web_application
            scan_smb
            scan_ftp
            scan_ssh
            scan_databases
            scan_mail_services
            scan_dns
            scan_firewall_ids
            scan_exploits
            scan_brute_force
            scan_network_analysis
            scan_vpn_tunnel
            scan_snmp
            ;;
    esac
}

# Parametreleri parse et
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -l|--level)
                SCAN_LEVEL="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="$2"
                shift 2
                ;;
            -f|--format)
                REPORT_FORMAT="$2"
                shift 2
                ;;
            --skip-slow)
                SKIP_SLOW=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Bilinmeyen parametre: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Ana program
main() {
    show_banner
    
    # Parametreleri parse et
    parse_arguments "$@"
    
    # Hedef kontrolü
    if [ -z "$TARGET" ]; then
        log_error "Hedef belirtilmedi!"
        show_help
        exit 1
    fi
    
    # Root kontrolü
    if [[ $EUID -ne 0 ]]; then
        log_error "Bu script root yetkisiyle çalıştırılmalıdır!"
        log_info "Kullanım: sudo $0 -t $TARGET"
        exit 1
    fi
    
    # Çıktı dizini oluştur
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="scan_${TARGET}_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$OUTPUT_DIR"
    
    # Gereksinimler
    check_requirements
    
    # Bilgi toplama
    gather_target_info
    
    # Taramayı başlat
    echo ""
    log_info "════════════════════════════════════════════════════"
    log_info "Hedef: $TARGET"
    log_info "Seviye: $SCAN_LEVEL"
    log_info "Çıktı: $OUTPUT_DIR"
    log_info "════════════════════════════════════════════════════"
    echo ""
    
    # Ana tarama
    run_scan
    
    # Raporları oluştur
    generate_summary_report
    generate_html_report
    
    # Tamamlandı
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                TARAMA BAŞARIYLA TAMAMLANDI!               ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Toplam Süre    :${NC} $((duration / 60)) dakika $((duration % 60)) saniye"
    echo -e "${CYAN}Sonuç Dizini   :${NC} $OUTPUT_DIR/"
    echo -e "${CYAN}Özet Rapor     :${NC} $OUTPUT_DIR/00_EXECUTIVE_SUMMARY.txt"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Özet raporu göster
    cat "$OUTPUT_DIR/00_EXECUTIVE_SUMMARY.txt"
}

# Scripti çalıştır
main "$@"
