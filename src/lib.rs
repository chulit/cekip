//! Logika inti cekip: parsing target (CIDR / range / IP tunggal),
//! enumerasi host, filter exclude, pembacaan tabel ARP, dan probing ping.
//!
//! Prinsip kejujuran data: IP yang tidak merespons ping DAN tidak ada di
//! tabel ARP dilaporkan sebagai `FreeCandidate`, bukan "pasti kosong" —
//! device yang sedang offline tetap tidak akan terdeteksi.

use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Batas jumlah host per scan supaya /8 tidak meledakkan memori & jaringan.
pub const MAX_HOSTS: u32 = 65_536;

// ---------------------------------------------------------------- target ---

/// Target scan: hasil parsing dari string user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Alamat jaringan + prefix, mis. 192.168.1.0/24
    Cidr { network: Ipv4Addr, prefix: u8 },
    /// Rentang inklusif, mis. 192.168.1.10-192.168.1.50
    Range { start: Ipv4Addr, end: Ipv4Addr },
    /// Satu IP saja.
    Single(Ipv4Addr),
}

impl Target {
    pub fn parse(s: &str) -> Result<Target, String> {
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            let start: Ipv4Addr = a.trim().parse().map_err(|_| format!("IP awal tidak valid: {a}"))?;
            let end: Ipv4Addr = b.trim().parse().map_err(|_| format!("IP akhir tidak valid: {b}"))?;
            if u32::from(end) < u32::from(start) {
                return Err("IP akhir lebih kecil dari IP awal".into());
            }
            return Ok(Target::Range { start, end });
        }
        if let Some((ip_s, prefix_s)) = s.split_once('/') {
            let ip: Ipv4Addr = ip_s.trim().parse().map_err(|_| format!("IP tidak valid: {ip_s}"))?;
            let prefix: u8 = prefix_s.trim().parse().map_err(|_| format!("prefix tidak valid: {prefix_s}"))?;
            if prefix > 32 {
                return Err("prefix harus 0-32".into());
            }
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let network = Ipv4Addr::from(u32::from(ip) & mask);
            return Ok(Target::Cidr { network, prefix });
        }
        let ip: Ipv4Addr = s.parse().map_err(|_| format!("target tidak dikenal: {s}"))?;
        Ok(Target::Single(ip))
    }

    /// Semua host yang akan diprobe.
    ///
    /// Untuk CIDR /0../30, network & broadcast address dikeluarkan.
    /// /31 dianggap point-to-point (kedua alamat dipakai), /32 satu host.
    pub fn hosts(&self) -> Result<Vec<Ipv4Addr>, String> {
        let (first, last) = match *self {
            Target::Single(ip) => (u32::from(ip), u32::from(ip)),
            Target::Range { start, end } => (u32::from(start), u32::from(end)),
            Target::Cidr { network, prefix } => {
                let base = u32::from(network);
                let total: u64 = 1u64 << (32 - prefix);
                let broadcast = base + (total as u32 - 1);
                match prefix {
                    32 => (base, base),
                    31 => (base, broadcast),
                    _ => (base + 1, broadcast - 1),
                }
            }
        };
        let count = (last as u64 - first as u64 + 1) as u32;
        if count > MAX_HOSTS {
            return Err(format!(
                "target terlalu besar: {count} host (maks {MAX_HOSTS}). Perkecil subnet / range-nya."
            ));
        }
        Ok((first..=last).map(Ipv4Addr::from).collect())
    }
}

// --------------------------------------------------------------- exclude ---

/// Daftar pengecualian: IP / CIDR / range yang tidak boleh ditawarkan
/// sebagai IP kosong (mis. gateway, range DHCP, IP statis server).
#[derive(Debug, Default)]
pub struct Excludes {
    ranges: Vec<(u32, u32)>,
}

impl Excludes {
    /// Parse format: "192.168.1.1,192.168.1.100-192.168.1.200,10.0.0.0/24"
    pub fn parse(s: &str) -> Result<Excludes, String> {
        let mut ex = Excludes::default();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match Target::parse(part)? {
                Target::Single(ip) => ex.ranges.push((u32::from(ip), u32::from(ip))),
                Target::Range { start, end } => ex.ranges.push((u32::from(start), u32::from(end))),
                Target::Cidr { network, prefix } => {
                    let base = u32::from(network);
                    let total: u64 = 1u64 << (32 - prefix);
                    ex.ranges.push((base, base + (total as u32 - 1)));
                }
            }
        }
        Ok(ex)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        self.ranges.iter().any(|(a, b)| v >= *a && v <= *b)
    }
}

// ------------------------------------------------------------------ ARP ----

/// Parse output `arp -a` (macOS / Linux / Windows) menjadi peta IP -> MAC.
pub fn parse_arp_a(output: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        // Format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
        let Some(start) = line.find('(') else { continue };
        let Some(end) = line[start..].find(')') else { continue };
        let ip_s = &line[start + 1..start + end];
        let Ok(ip) = ip_s.parse::<Ipv4Addr>() else { continue };
        let Some(at) = line.find(" at ") else { continue };
        let mac = line[at + 4..].split_whitespace().next().unwrap_or("");
        if is_valid_mac(mac) {
            map.insert(ip, mac.to_lowercase());
        }
    }
    map
}

/// Parse isi `/proc/net/arp` (Linux). Hanya entri lengkap (flags 0x2).
pub fn parse_proc_net_arp(content: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // IP | HW type | Flags | HW address | Mask | Device
        if cols.len() < 4 {
            continue;
        }
        if cols[2] != "0x2" {
            continue;
        }
        let Ok(ip) = cols[0].parse::<Ipv4Addr>() else { continue };
        if is_valid_mac(cols[3]) {
            map.insert(ip, cols[3].to_lowercase());
        }
    }
    map
}

fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6
        && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        && s != "00:00:00:00:00:00"
}

/// Baca tabel ARP sistem saat ini (setelah ping sweep, tabel ini terisi
/// untuk host-host lokal yang hidup).
pub fn read_arp_table() -> HashMap<Ipv4Addr, String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            let map = parse_proc_net_arp(&content);
            if !map.is_empty() {
                return map;
            }
        }
    }
    if let Ok(out) = Command::new("arp").arg("-a").output() {
        return parse_arp_a(&String::from_utf8_lossy(&out.stdout));
    }
    HashMap::new()
}

// ---------------------------------------------------------------- probe ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Merespons ping atau ada di tabel ARP.
    Used,
    /// Tidak merespons ping dan tidak ada di ARP — kandidat kosong.
    FreeCandidate,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Port TCP yang membuktikan host hidup bila ping gagal (opsional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_port: Option<u16>,
    /// true bila user meng-exclude IP ini (tetap diprobe, ditandai saja).
    pub excluded: bool,
}

/// Keputusan status murni dari tiga sinyal — dipisah supaya bisa ditest.
pub fn decide_status(ping_ok: bool, in_arp: bool, tcp_alive: bool) -> Status {
    if ping_ok || in_arp || tcp_alive {
        Status::Used
    } else {
        Status::FreeCandidate
    }
}

/// Port TCP umum untuk probing cadangan. Koneksi yang berhasil ATAU
/// ditolak (RST) sama-sama membuktikan host-nya hidup — yang membedakan
/// IP kosong adalah timeout / tidak ada rute.
const TCP_PROBE_PORTS: [u16; 7] = [80, 443, 22, 53, 445, 3389, 8080];

/// Probe TCP: mengembalikan port pertama yang membuktikan host hidup.
/// Dipakai bila ping gagal (banyak device & sandbox memblokir ICMP).
pub fn tcp_probe(ip: Ipv4Addr, timeout: Duration) -> Option<u16> {
    use std::net::{SocketAddr, TcpStream};
    for port in TCP_PROBE_PORTS {
        let addr = SocketAddr::from((ip, port));
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => return Some(port),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Some(port),
            _ => {}
        }
    }
    None
}

/// Ping satu host memakai binary `ping` bawaan OS (tidak butuh root /
/// raw socket). Mengembalikan latency kasar bila host merespons.
pub fn ping(ip: Ipv4Addr, timeout: Duration) -> Option<Duration> {
    let timeout_ms = timeout.as_millis().max(100);
    let mut cmd = Command::new("ping");
    #[cfg(target_os = "windows")]
    cmd.args(["-n", "1", "-w", &timeout_ms.to_string()]);
    #[cfg(target_os = "macos")]
    // macOS: -W dalam milidetik
    cmd.args(["-c", "1", "-W", &timeout_ms.to_string()]);
    #[cfg(all(unix, not(target_os = "macos")))]
    // Linux: -W dalam detik (dibulatkan ke atas, min 1)
    cmd.args(["-c", "1", "-W", &((timeout_ms as f64 / 1000.0).ceil().max(1.0) as u64).to_string()]);
    cmd.arg(ip.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let started = Instant::now();
    match cmd.status() {
        Ok(s) if s.success() => Some(started.elapsed()),
        _ => None,
    }
}

/// Probe banyak host secara concurrent (scoped threads, tanpa async runtime).
pub fn scan(
    hosts: &[Ipv4Addr],
    excludes: &Excludes,
    timeout: Duration,
    concurrency: usize,
) -> Vec<HostResult> {
    let concurrency = concurrency.max(1);
    // (latency ping, port TCP bukti hidup)
    let mut probe_results: HashMap<Ipv4Addr, (Option<Duration>, Option<u16>)> = HashMap::new();

    for chunk in hosts.chunks(concurrency) {
        let probed: Vec<(Ipv4Addr, Option<Duration>, Option<u16>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|&ip| {
                    scope.spawn(move || {
                        let latency = ping(ip, timeout);
                        // Ping gagal bukan vonis: coba bukti TCP (timeout
                        // dipangkas supaya host kosong tidak lama ditunggu).
                        let tcp = if latency.is_none() {
                            tcp_probe(ip, Duration::from_millis(250))
                        } else {
                            None
                        };
                        (ip, latency, tcp)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("thread probe panik")).collect()
        });
        for (ip, latency, tcp) in probed {
            probe_results.insert(ip, (latency, tcp));
        }
    }

    // ARP dibaca SETELAH sweep: ping mengisi ARP cache untuk host lokal.
    let arp = read_arp_table();

    let mut results: Vec<HostResult> = hosts
        .iter()
        .map(|&ip| {
            let (latency, tcp_port) = probe_results.get(&ip).copied().unwrap_or((None, None));
            let mac = arp.get(&ip).cloned();
            HostResult {
                ip,
                status: decide_status(latency.is_some(), mac.is_some(), tcp_port.is_some()),
                mac,
                latency_ms: latency.map(|d| d.as_millis() as u64),
                tcp_port,
                excluded: excludes.contains(ip),
            }
        })
        .collect();
    results.sort_by_key(|r| u32::from(r.ip));
    results
}

// ------------------------------------------------------- cek akses URL ---
//
// IP yang kosong tidak punya device, jadi "apakah IP X bisa akses YouTube"
// hanya bisa dijawab dengan *memakai* IP itu sebentar dari mesin ini:
// pasang alias IP di interface, kirim request dengan IP sumber = alias
// (curl --interface), lalu lepas alias-nya. Hasilnya mencerminkan aturan
// firewall/proxy jaringan untuk IP sumber tersebut.

/// Hasil satu kali cek URL dari sebuah IP sumber.
#[derive(Debug, Clone, Serialize)]
pub struct UrlAccess {
    pub http_status: Option<u16>,
    /// true bila HTTP 2xx/3xx — halaman benar-benar bisa dibuka.
    pub accessible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Rapikan satu URL dari user: "youtube.com" -> "https://youtube.com".
/// Yang sudah berskema (mengandung "://") dibiarkan apa adanya.
pub fn normalize_url(raw: &str) -> String {
    let s = raw.trim();
    if s.contains("://") {
        s.to_string()
    } else {
        format!("https://{s}")
    }
}

/// Gabungkan masukan URL dari banyak sumber (--url berulang dan/atau
/// daftar pisah-koma), normalisasi, buang duplikat, pertahankan urutan.
pub fn collect_urls(inputs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for input in inputs {
        for part in input.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let url = normalize_url(part);
            if !out.contains(&url) {
                out.push(url);
            }
        }
    }
    out
}

/// Label pendek sebuah URL untuk tampilan: host-nya saja.
pub fn url_host(url: &str) -> String {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    after_scheme.split('/').next().unwrap_or(after_scheme).to_string()
}

/// "200" -> Some(200); "000" (curl gagal total) & sampah -> None.
pub fn parse_curl_code(out: &str) -> Option<u16> {
    match out.trim() {
        "000" | "" => None,
        s => s.parse().ok(),
    }
}

pub fn is_accessible(code: Option<u16>) -> bool {
    matches!(code, Some(c) if (200..=399).contains(&c))
}

/// Cek URL memakai `source` (nama interface atau IP) sebagai alamat sumber,
/// via curl bawaan sistem (TLS & redirect ditangani curl).
pub fn check_url(source: &str, url: &str, timeout: Duration) -> UrlAccess {
    let out = Command::new("curl")
        .args([
            "-s",
            "-L",
            "--max-redirs",
            "5",
            "-o",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
            "-w",
            "%{http_code}",
            "--interface",
            source,
            "--max-time",
            &timeout.as_secs().max(1).to_string(),
            url,
        ])
        .output();
    match out {
        Ok(o) => {
            let code = parse_curl_code(&String::from_utf8_lossy(&o.stdout));
            UrlAccess {
                http_status: code,
                accessible: is_accessible(code),
                error: if code.is_none() {
                    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    Some(if err.is_empty() { "tidak ada respons".into() } else { err })
                } else {
                    None
                },
            }
        }
        Err(e) => UrlAccess { http_status: None, accessible: false, error: Some(format!("curl tidak bisa dijalankan: {e}")) },
    }
}

// ----------------------------------------------------------------- alias ---

pub fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else if prefix >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
    } else {
        Ipv4Addr::from(u32::MAX << (32 - prefix))
    }
}

/// Perintah (via sudo) memasang alias IP di interface.
pub fn alias_add_command(iface: &str, ip: Ipv4Addr, prefix: u8) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        vec!["sudo".into(), "ifconfig".into(), iface.into(), "alias".into(), ip.to_string(), prefix_to_netmask(prefix).to_string()]
    }
    #[cfg(not(target_os = "macos"))]
    {
        vec!["sudo".into(), "ip".into(), "addr".into(), "add".into(), format!("{ip}/{prefix}"), "dev".into(), iface.into()]
    }
}

/// Perintah (via sudo) melepas alias IP dari interface.
pub fn alias_remove_command(iface: &str, ip: Ipv4Addr, prefix: u8) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let _ = prefix;
        vec!["sudo".into(), "ifconfig".into(), iface.into(), "-alias".into(), ip.to_string()]
    }
    #[cfg(not(target_os = "macos"))]
    {
        vec!["sudo".into(), "ip".into(), "addr".into(), "del".into(), format!("{ip}/{prefix}"), "dev".into(), iface.into()]
    }
}

fn run_command(cmd: &[String]) -> Result<(), String> {
    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .status()
        .map_err(|e| format!("gagal menjalankan {}: {e}", cmd.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("perintah gagal ({}): {}", status, cmd.join(" ")))
    }
}

/// Pasang alias IP, jalankan `f`, lalu SELALU lepas alias-nya lagi
/// (termasuk bila `f` mengembalikan hasil gagal di level aplikasi).
pub fn with_alias<T>(iface: &str, ip: Ipv4Addr, prefix: u8, f: impl FnOnce() -> T) -> Result<T, String> {
    run_command(&alias_add_command(iface, ip, prefix))?;
    let result = f();
    let removed = run_command(&alias_remove_command(iface, ip, prefix));
    removed.map(|_| result)
}

// ----------------------------------------------------------------- tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_cidr_normalizes_network() {
        assert_eq!(
            Target::parse("192.168.1.77/24").unwrap(),
            Target::Cidr { network: ip("192.168.1.0"), prefix: 24 }
        );
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        assert!(Target::parse("192.168.1.0/33").is_err());
        assert!(Target::parse("bukan-ip/24").is_err());
    }

    #[test]
    fn hosts_24_excludes_network_and_broadcast() {
        let hosts = Target::parse("192.168.1.0/24").unwrap().hosts().unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], ip("192.168.1.1"));
        assert_eq!(hosts[253], ip("192.168.1.254"));
    }

    #[test]
    fn hosts_small_prefixes() {
        assert_eq!(Target::parse("10.0.0.0/30").unwrap().hosts().unwrap().len(), 2);
        assert_eq!(Target::parse("10.0.0.0/31").unwrap().hosts().unwrap().len(), 2);
        assert_eq!(Target::parse("10.0.0.5/32").unwrap().hosts().unwrap().len(), 1);
    }

    #[test]
    fn hosts_rejects_huge_network() {
        assert!(Target::parse("10.0.0.0/8").unwrap().hosts().is_err());
    }

    #[test]
    fn parse_range_and_single() {
        let hosts = Target::parse("192.168.1.10-192.168.1.12").unwrap().hosts().unwrap();
        assert_eq!(hosts, vec![ip("192.168.1.10"), ip("192.168.1.11"), ip("192.168.1.12")]);
        assert!(Target::parse("192.168.1.12-192.168.1.10").is_err());
        assert_eq!(Target::parse("192.168.1.9").unwrap().hosts().unwrap().len(), 1);
    }

    #[test]
    fn excludes_match_single_cidr_and_range() {
        let ex = Excludes::parse("192.168.1.1,192.168.1.100-192.168.1.110,10.0.0.0/30").unwrap();
        assert!(ex.contains(ip("192.168.1.1")));
        assert!(ex.contains(ip("192.168.1.105")));
        assert!(ex.contains(ip("10.0.0.2")));
        assert!(!ex.contains(ip("192.168.1.50")));
    }

    #[test]
    fn parse_arp_a_macos_format() {
        let out = "? (192.168.1.1) at AA:BB:CC:DD:EE:FF on en0 ifscope [ethernet]\n\
                   ? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n";
        let map = parse_arp_a(out);
        assert_eq!(map.get(&ip("192.168.1.1")).map(String::as_str), Some("aa:bb:cc:dd:ee:ff"));
        assert!(!map.contains_key(&ip("192.168.1.2")));
    }

    #[test]
    fn parse_proc_net_arp_linux_format() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                       192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let map = parse_proc_net_arp(content);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&ip("192.168.1.1")));
    }

    #[test]
    fn netmask_from_prefix() {
        assert_eq!(prefix_to_netmask(24), ip("255.255.255.0"));
        assert_eq!(prefix_to_netmask(16), ip("255.255.0.0"));
        assert_eq!(prefix_to_netmask(30), ip("255.255.255.252"));
        assert_eq!(prefix_to_netmask(0), ip("0.0.0.0"));
        assert_eq!(prefix_to_netmask(32), ip("255.255.255.255"));
    }

    #[test]
    fn url_normalization_and_collection() {
        assert_eq!(normalize_url("youtube.com"), "https://youtube.com");
        assert_eq!(normalize_url("https://a.com/x"), "https://a.com/x");
        assert_eq!(normalize_url(" http://b.com "), "http://b.com");
        let inputs = vec![
            "youtube.com, https://netflix.com".to_string(),
            "youtube.com".to_string(),
            "http://c.com/path".to_string(),
        ];
        assert_eq!(
            collect_urls(&inputs),
            vec!["https://youtube.com", "https://netflix.com", "http://c.com/path"]
        );
        assert_eq!(url_host("https://www.youtube.com/watch?v=1"), "www.youtube.com");
        assert_eq!(url_host("http://127.0.0.1:18923/"), "127.0.0.1:18923");
    }

    #[test]
    fn curl_code_and_accessibility() {
        assert_eq!(parse_curl_code("200"), Some(200));
        assert_eq!(parse_curl_code("000"), None);
        assert_eq!(parse_curl_code("sampah"), None);
        assert!(is_accessible(Some(200)));
        assert!(is_accessible(Some(301)));
        assert!(!is_accessible(Some(403)));
        assert!(!is_accessible(Some(404)));
        assert!(!is_accessible(None));
    }

    #[test]
    fn alias_commands_shape() {
        let add = alias_add_command("en6", ip("10.0.0.50"), 24);
        let del = alias_remove_command("en6", ip("10.0.0.50"), 24);
        assert_eq!(add[0], "sudo");
        assert!(add.iter().any(|a| a.contains("10.0.0.50")));
        assert!(del.iter().any(|a| a.contains("10.0.0.50")));
        assert_ne!(add, del);
    }

    #[test]
    fn status_decision() {
        assert_eq!(decide_status(true, false, false), Status::Used);
        assert_eq!(decide_status(false, true, false), Status::Used);
        assert_eq!(decide_status(false, false, true), Status::Used);
        assert_eq!(decide_status(false, false, false), Status::FreeCandidate);
    }
}
