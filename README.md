# Censorship Levels Guide  
راهنمای تشخیص سطوح فیلترینگ + انتخاب پروتکل تونل مناسب

![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-yellow.svg?style=flat-square)
![Language](https://img.shields.io/badge/language-Persian-blue?style=flat-square)
![Last Updated](https://img.shields.io/badge/last%20update-February%202026-blue?style=flat-square)

### هدف پروژه
تشخیص دقیق سطح فیلترینگ بین سرور داخل ایران و سرور خارج  
و ارائه عملی‌ترین پروتکل/روش تونلینگ برای شرایط فعلی (۱۴۰۴–۱۴۰۵)

### سطوح فیلترینگ

| سطح | نام سطح                     | نشانه اصلی                              | راه‌حل پیشنهادی (به‌روز ۱۴۰۴–۱۴۰۵)                     |
|-----|-----------------------------|------------------------------------------|----------------------------------------------------------|
| 1   | ICMP Blocking               | ping بسته، tcp/udp باز                  | هر تونل TCP (socat, iptables NAT, ssh tunnel)           |
| 2   | Port Blocking               | برخی پورت‌ها بسته                       | پورت 443 یا 80                                          |
| 3   | IP Blacklist                | همه پورت‌ها به IP خاص بسته             | CDN (Cloudflare/Gcore)، Relay، تغییر IP                 |
| 4   | Stateful Inspection (SPI)   | اتصال بعد از مدتی قطع می‌شود           | mux / Hysteria2 / TUIC / WireGuard                       |
| 5   | Deep Packet Inspection      | پروتکل شناسایی و بلاک می‌شود           | Reality / ShadowTLS v3 / uTLS + WS/CDN / Hysteria2      |
| 6   | Protocol Whitelisting       | فقط پروتکل/دامنه‌های مجاز کار می‌کند   | DNS Tunneling (dnstt) – بسیار سخت و کند                |

### اسکریپت تشخیص سطح فیلترینگ

**فایل:** `scripts/detect-level.sh`  
**نسخه فعلی:** **3.0** (بهمن ۱۴۰۴ / فوریه ۲۰۲۶)  
**ویژگی‌های اصلی نسخه ۳:**  
• تست‌های جامع (TCP + UDP + TLS + HTTP + DNS + Traceroute + MTU)  
• تشخیص DPI و Active Probing  
• تست پایداری طولانی اتصال  
• رابط کاربری حرفه‌ای با رنگ، لاگ‌گیری و تحلیل دقیق  
• پیشنهاد تونل به‌روز برای هر سطح

**بهترین روش اجرا (دقیق‌ترین نتیجه):**  
روی VPS خارج از ایران اجرا کنید و IP سرور داخل ایران را بدهید.

```bash
# دانلود نسخه ۳.۰
curl -L https://github.com/Arashtelr/censorship-levels-guide/releases/download/v3.0/detect-level.sh -o detect.sh

# یا از raw (اگر release هنوز ساخته نشده)
# curl -L https://raw.githubusercontent.com/Arashtelr/censorship-levels-guide/main/scripts/detect-level.sh -o detect.sh

chmod +x detect.sh

# اجرا
./detect.sh 185.XX.XX.XX
