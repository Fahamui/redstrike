# RedStrike Suite v2.0

Modüler siber güvenlik tarayıcısı — bug bounty ve pentest için.

## 🚀 Özellikler

- **Recon** — Domain, IP, whois, server bilgisi
- **Port Scanner** — 17 port taraması + banner grab
- **Banner Grab** — SSH, FTP, HTTP, POP3, IMAP versiyonları
- **FTP Check** — Anonymous FTP kontrolü
- **Endpoint** — 300+ kelime ile dizin keşfi
- **Web Vuln** — SQLi, XSS, LFI, PHP hata sızıntısı
- **Subdomain** — Wildcard DNS tespiti ile
- **SSL/TLS** — Sertifika, CA, cipher, süre analizi
- **IP Intel** — ASN, ülke, şehir bilgisi
- **Rate Limit** — Ban koruması + zafiyet testi
- **Scope Manager** — Yasal güvence (bug bounty)

## 📦 Kurulum

```bash
git clone https://github.com/Fahamui/redstrike.git
cd redstrike
pip install -r requirements.txt
python main.py
