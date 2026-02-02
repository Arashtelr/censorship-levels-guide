# Censorship Levels Guide

راهنمای تشخیص سطوح فیلترینگ + انتخاب پروتکل تونل مناسب

![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-yellow.svg?style=flat-square)
![Language](https://img.shields.io/badge/language-Persian-blue?style=flat-square)
![Last Updated](https://img.shields.io/badge/last%20update-February%202026-blue?style=flat-square)

### هدف پروژه
تشخیص سطح فیلترینگ بین سرور داخل ایران و سرور خارج  
و پیشنهاد عملی‌ترین پروتکل تونل برای شرایط فعلی (۱۴۰۴–۱۴۰۵)

### سطوح فیلترینگ

| سطح | نام سطح                     | نشانه اصلی                              | راه‌حل پیشنهادی (به‌روز)                     |
|-----|-----------------------------|------------------------------------------|------------------------------------------------|
| 1   | ICMP Blocking               | ping بسته، tcp/udp باز                  | هر تونل TCP (socat, iptables NAT, ssh)        |
| 2   | Port Blocking               | برخی پورت‌ها بسته                       | پورت 443 یا 80                                |
| 3   | IP Blacklist                | همه پورت‌ها به IP خاص بسته             | CDN (Cloudflare/Gcore)، Relay، تغییر IP       |
| 4   | Stateful Inspection (SPI)   | اتصال بعد از مدتی قطع می‌شود           | mux / Hysteria2 / TUIC / WireGuard             |
| 5   | Deep Packet Inspection      | پروتکل شناسایی و بلاک می‌شود           | Reality / ShadowTLS v3 / uTLS + WS/CDN         |
| 6   | Protocol Whitelisting       | فقط پروتکل/دامنه‌های مجاز کار می‌کند   | DNS Tunneling (dnstt) – بسیار سخت             |

### اسکریپت تشخیص سطح

**فایل:** `scripts/detect-level.sh`  
**نسخه فعلی:** 2.0 (بهمن ۱۴۰۴)

**بهترین روش اجرا (دقیق‌ترین نتیجه):**

روی VPS خارج از ایران اجرا کنید و IP سرور داخل ایران را بدهید.

```bash
# دانلود آخرین نسخه
curl -L https://raw.githubusercontent.com/Arashtelr/censorship-levels-guide/main/scripts/detect-level.sh -o detect.sh

chmod +x detect.sh

# اجرا
./detect.sh 185.XX.XX.XX
