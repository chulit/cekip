# cekip

CLI kecil (Rust, satu binary) untuk mencari **IP yang belum dipakai** di sebuah subnet —
buat pas mau pasang IP statis tanpa takut bentrok.

## Cara kerja

Satu IP dinyatakan `USED` bila ada **salah satu** bukti hidup:

1. **Ping (ICMP)** merespons
2. **Ada di tabel ARP** sistem (paling kuat untuk subnet lokal — device yang
   memblokir ping pun tetap ketahuan, lengkap dengan MAC address)
3. **Probe TCP** ke port umum (80, 443, 22, 53, 445, 3389, 8080) berhasil
   tersambung *atau* ditolak (RST) — keduanya membuktikan host-nya ada

IP tanpa satu pun bukti di atas dilaporkan `FREE` (**kandidat** kosong).
Device yang sedang *mati/offline* tidak akan terdeteksi oleh tool mana pun —
jadi verifikasi sekali lagi sebelum benar-benar memakai IP-nya.

## Pakai

```bash
# scan satu subnet penuh
cekip scan 192.168.1.0/24

# cari 10 IP kosong pertama, hindari gateway & range DHCP
cekip scan 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.100-192.168.1.200
cekip free 192.168.1.0/24 --count 10 --exclude 192.168.1.1

# target bisa juga berupa range atau IP tunggal
cekip scan 192.168.1.10-192.168.1.50
cekip check 192.168.1.50

# format lain buat diolah script / disimpan
cekip scan 192.168.1.0/24 --format json
cekip scan 192.168.1.0/24 --format csv
```

Opsi: `--timeout-ms` (default 800), `--concurrency` (default 64).
Batas keamanan: maksimal 65.536 host per scan.

Contoh output:

```
IP               STATUS   MAC                 LATENCY   TCP       EXCLUDED
192.168.1.1      USED     da:c1:a4:cd:33:62   -         :53       -
192.168.1.2      USED     -                   -         :80       -
192.168.1.3      FREE     -                   -         -         -
```

Kolom `TCP` = port yang membuktikan host hidup (tersambung **atau** ditolak
pakai RST — bukan jaminan port itu terbuka).

## Build

```bash
cargo build --release   # binary di target/release/cekip
cargo test              # 10 unit test: parsing CIDR/range, exclude, ARP, keputusan status
```

Tidak butuh hak root: ping memakai binary `ping` bawaan OS, ARP dibaca dari
tabel sistem (`/proc/net/arp` di Linux, `arp -a` di macOS/Windows).

## Batasan jujur

- Paling akurat di **subnet lokal yang sama** (ARP hanya bekerja satu segmen LAN).
- Di jaringan yang punya proxy/firewall di tengah, jawaban TCP bisa
  false-positive (yang menolak koneksi bisa jadi perangkat tengah, bukan host tujuan).
- `FREE` artinya "tidak ada bukti hidup saat scan", bukan garansi kosong selamanya.

## Roadmap (kalau mau lanjut)

- Reverse DNS / hostname (mDNS) di output
- Cek lease DHCP dari router (SNMP/UPnP)
- Mode `--watch`: scan berkala & bunyi kalau ada IP konflik
