# Censorship Levels Guide

راهنمای جامع تشخیص سطوح فیلترینگ اینترنت + انتخاب پروتکل تونل مناسب

![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-yellow.svg?style=flat-square)
![Language](https://img.shields.io/badge/language-Persian-blue?style=flat-square)
![Last Updated](https://img.shields.io/badge/last%20update-February%202026-blue?style=flat-square)

**هدف پروژه**  
کمک به تشخیص دقیق سطح فیلترینگ اعمال‌شده روی ارتباط بین دو سرور (داخل ایران ↔ خارج از کشور) و پیشنهاد **بهترین و به‌روزترین** روش تونلینگ برای هر سطح.

این راهنما بر اساس رفتار واقعی فایروال و DPI ایران در سال ۱۴۰۴–۱۴۰۵ (۲۰۲۵–۲۰۲۶) تهیه شده و مرتب به‌روزرسانی می‌شود.

### چرا این پروژه مفید است؟

- تشخیص می‌دهد فیلترینگ در کدام لایه (L3, L4, L7) اعمال می‌شود
- مشخص می‌کند کدام پروتکل‌ها احتمالاً هنوز کار می‌کنند
- راه‌حل‌های عملی و تست‌شده برای هر سطح ارائه می‌دهد
- شامل اسکریپت تشخیص خودکار سطح فیلترینگ است

### سطوح فیلترینگ پوشش داده شده

| سطح | نام سطح                     | نشانه اصلی تشخیص                     | راه‌حل پیشنهادی (به‌روز ۱۴۰۴–۱۴۰۵)                  |
|-----|-----------------------------|---------------------------------------|-----------------------------------------------------|
| 1   | ICMP Blocking               | ping کار نمی‌کند، tcp/udp باز است     | هر تونل TCP (socat, iptables NAT, ssh tunnel)      |
| 2   | Port Blocking               | بعضی پورت‌ها بسته (مثل 22, 8080)      | استفاده از پورت‌های مجاز (443, 80, گاهی 53)       |
| 3   | IP Blacklist                | همه پورت‌ها به IP خاص بسته           | CDN (Cloudflare, Gcore)، Relay، تغییر IP           |
| 4   | Stateful Inspection (SPI)   | اتصال بعد چند دقیقه قطع می‌شود       | Multiplexing (mux)، UDP-based (Hysteria2, TUIC, WireGuard) |
| 5   | Deep Packet Inspection (DPI)| پروتکل شناسایی و بلاک می‌شود         | Reality, ShadowTLS v3, uTLS + WS/gRPC + CDN, Hysteria2 |
| 6   | Protocol Whitelisting + MITM| فقط پروتکل/دامنه‌های مجاز کار می‌کند | DNS Tunneling (dnstt), بسیار سخت و کند             |

### نحوه استفاده از اسکریپت تشخیص سطح

**مهم‌ترین توصیه برای دقت بالا:**

بهترین نتیجه وقتی به دست می‌آید که اسکریپت را **از خارج ایران** اجرا کنید و IP **سرور داخل ایران** را بدهید.

```bash
# روی VPS خارج (آلمان، هلند، فنلاند و ...) اجرا کنید
chmod +x scripts/detect-level.sh
./scripts/detect-level.sh 185.XX.XX.XX
