use cekip::{check_url, collect_urls, scan, url_host, with_alias, Excludes, HostResult, Status, Target};
use clap::{Parser, Subcommand, ValueEnum};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "cekip", version, about = "Cari IP yang belum dipakai di sebuah subnet")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan semua host di target dan tampilkan statusnya
    Scan {
        /// Target: CIDR (192.168.1.0/24), range (192.168.1.10-192.168.1.50), atau IP tunggal
        target: String,
        #[command(flatten)]
        opts: Opts,
    },
    /// Tampilkan hanya IP yang (kemungkinan) belum dipakai
    Free {
        /// Target: CIDR, range, atau IP tunggal
        target: String,
        /// Jumlah IP kosong maksimal yang ditampilkan
        #[arg(long, default_value_t = 10)]
        count: usize,
        #[command(flatten)]
        opts: Opts,
    },
    /// Cari IP kosong yang BISA mengakses URL tertentu (IP dipasang
    /// sementara sebagai alias di interface kamu, diuji, lalu dilepas).
    /// URL bebas sesuai keinginan: --url bisa diulang / dipisah koma,
    /// dan kalau tidak diisi akan ditanyakan saat perintah dijalankan.
    FreeUrl {
        /// Target: CIDR, range, atau IP tunggal
        target: String,
        /// URL yang diuji, mis. --url youtube.com --url netflix.com
        /// atau --url "youtube.com,netflix.com". Tanpa skema boleh
        /// (otomatis https://). Kosong = ditanya interaktif.
        #[arg(long)]
        url: Vec<String>,
        /// Interface tempat alias dipasang, mis. en6 (Ethernet) / en0 (Wi-Fi)
        #[arg(long)]
        interface: String,
        /// Berhenti setelah menemukan sebanyak ini IP yang lolos SEMUA URL
        #[arg(long, default_value_t = 5)]
        count: usize,
        /// Maksimal kandidat IP kosong yang diuji satu per satu
        #[arg(long, default_value_t = 20)]
        test_limit: usize,
        /// Prefix subnet untuk alias (default: dari CIDR target, atau 24)
        #[arg(long)]
        prefix: Option<u8>,
        /// Timeout cek URL per IP (ms)
        #[arg(long, default_value_t = 10_000)]
        url_timeout_ms: u64,
        /// Lewati konfirmasi (alias dipasang/dilepas tanpa ditanya)
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        opts: Opts,
    },
    /// Cek satu IP spesifik
    Check {
        /// IP yang mau dicek, mis. 192.168.1.50
        ip: Ipv4Addr,
        /// Timeout ping per host (ms)
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
    },
}

#[derive(clap::Args)]
struct Opts {
    /// Timeout ping per host (ms)
    #[arg(long, default_value_t = 800)]
    timeout_ms: u64,
    /// Jumlah ping paralel
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
    /// IP/range yang dikecualikan (dipisah koma), mis. "192.168.1.1,192.168.1.100-192.168.1.200"
    #[arg(long, default_value = "")]
    exclude: String,
    /// Format output
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Table,
    Json,
    Csv,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Check { ip, timeout_ms } => {
            let results = scan(
                &[ip],
                &Excludes::default(),
                Duration::from_millis(timeout_ms),
                1,
            );
            print_results(&results, &Format::Table);
            Ok(())
        }
        Command::Scan { target, opts } => {
            let results = scan_target(&target, &opts)?;
            print_results(&results, &opts.format);
            print_summary(&results);
            Ok(())
        }
        Command::Free { target, count, opts } => {
            let results = scan_target(&target, &opts)?;
            let free: Vec<HostResult> = results
                .into_iter()
                .filter(|r| r.status == Status::FreeCandidate && !r.excluded)
                .take(count)
                .collect();
            if free.is_empty() {
                println!("Tidak ada IP kosong ditemukan (di luar yang di-exclude).");
            } else {
                print_results(&free, &opts.format);
                println!(
                    "\nCatatan: status FREE = tidak merespons ping & tidak ada di tabel ARP\n\
                     saat scan. Device yang sedang mati tetap tidak terdeteksi —\n\
                     verifikasi sekali lagi sebelum IP dipakai statis."
                );
            }
            Ok(())
        }
        Command::FreeUrl { target, url, interface, count, test_limit, prefix, url_timeout_ms, yes, opts } => {
            free_url(&target, &url, &interface, count, test_limit, prefix, url_timeout_ms, yes, &opts)
        }
    }
}

/// (IP, [(url, http_status, accessible)])
type TestedIp = (Ipv4Addr, Vec<(String, Option<u16>, bool)>);

fn free_url(
    target: &str,
    url_inputs: &[String],
    interface: &str,
    count: usize,
    test_limit: usize,
    prefix: Option<u8>,
    url_timeout_ms: u64,
    yes: bool,
    opts: &Opts,
) -> Result<(), String> {
    // URL sepenuhnya pilihan user: dari --url (berulang / koma), atau
    // ditanyakan di terminal, atau default YouTube bila Enter saja.
    let mut urls = collect_urls(url_inputs);
    if urls.is_empty() {
        let answer = prompt_line("URL yang mau diuji (boleh lebih dari satu, pisahkan koma) [Enter = https://www.youtube.com]: ");
        urls = collect_urls(&[answer]);
        if urls.is_empty() {
            urls = vec!["https://www.youtube.com".to_string()];
        }
    }

    let parsed = Target::parse(target)?;
    let alias_prefix = match &parsed {
        Target::Cidr { prefix: p, .. } => prefix.unwrap_or(*p),
        _ => prefix.unwrap_or(24),
    };
    let hosts = parsed.hosts()?;
    let excludes = Excludes::parse(&opts.exclude)?;
    eprintln!("Scanning {} host untuk kandidat kosong...", hosts.len());
    let results = scan(&hosts, &excludes, Duration::from_millis(opts.timeout_ms), opts.concurrency);
    let candidates: Vec<Ipv4Addr> = results
        .iter()
        .filter(|r| r.status == Status::FreeCandidate && !r.excluded)
        .map(|r| r.ip)
        .take(test_limit)
        .collect();
    if candidates.is_empty() {
        println!("Tidak ada kandidat IP kosong untuk diuji.");
        return Ok(());
    }

    println!(
        "\nAkan menguji akses ke {} dari maksimal {} kandidat IP kosong pertama.\n\
         Caranya: tiap IP dipasang SEMENTARA sebagai alias di {interface} (butuh sudo),\n\
         request dikirim dari IP itu, lalu alias langsung dilepas lagi.\n",
        urls.join(", "),
        candidates.len()
    );
    if !yes && !confirm("Lanjut? [y/N] ") {
        println!("Dibatalkan.");
        return Ok(());
    }

    let mut passed: Vec<Ipv4Addr> = Vec::new();
    let mut tested: Vec<TestedIp> = Vec::new();
    for ip in &candidates {
        eprintln!("Menguji {ip} via {interface}...");
        let accesses = with_alias(interface, *ip, alias_prefix, || {
            urls.iter()
                .map(|u| check_url(&ip.to_string(), u, Duration::from_millis(url_timeout_ms)))
                .collect::<Vec<_>>()
        })?;
        let mut rows = Vec::new();
        let mut all_ok = true;
        for (u, a) in urls.iter().zip(&accesses) {
            eprintln!(
                "  {} -> {} {}",
                url_host(u),
                a.http_status.map(|c| format!("HTTP {c}")).unwrap_or_else(|| "tidak ada respons".into()),
                if a.accessible { "(BISA)" } else { "(tidak bisa)" }
            );
            all_ok &= a.accessible;
            rows.push((u.clone(), a.http_status, a.accessible));
        }
        tested.push((*ip, rows));
        if all_ok {
            passed.push(*ip);
            if passed.len() >= count {
                break;
            }
        }
    }

    println!("\n{:<16} {:<28} {:<8} {}", "IP", "URL", "HTTP", "AKSES");
    for (ip, rows) in &tested {
        for (u, code, ok) in rows {
            println!(
                "{:<16} {:<28} {:<8} {}",
                ip.to_string(),
                url_host(u),
                code.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                if *ok { "BISA" } else { "tidak" }
            );
        }
    }
    if passed.is_empty() {
        println!("\nTidak ada kandidat yang bisa mengakses semua URL itu dari {interface}.");
    } else {
        println!(
            "\n{} IP kosong lolos semua URL: {}",
            passed.len(),
            passed.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ")
        );
        println!("Catatan: hasil = aturan firewall/proxy jaringan untuk IP sumber tsb, diuji dari mesin ini.\nSebelum IP dipakai permanen, cek ulang sekali lagi (IP kosong bisa saja terisi device lain kapan pun).");
    }
    Ok(())
}

fn prompt_line(prompt: &str) -> String {
    use std::io::Write;
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

fn confirm(prompt: &str) -> bool {
    matches!(prompt_line(prompt).to_lowercase().as_str(), "y" | "ya")
}

fn scan_target(target: &str, opts: &Opts) -> Result<Vec<HostResult>, String> {
    let hosts = Target::parse(target)?.hosts()?;
    let excludes = Excludes::parse(&opts.exclude)?;
    eprintln!("Scanning {} host (timeout {} ms, {} paralel)...", hosts.len(), opts.timeout_ms, opts.concurrency);
    Ok(scan(&hosts, &excludes, Duration::from_millis(opts.timeout_ms), opts.concurrency))
}

fn print_summary(results: &[HostResult]) {
    let used = results.iter().filter(|r| r.status == Status::Used).count();
    eprintln!("\nTotal {} host: {} terpakai, {} kandidat kosong.", results.len(), used, results.len() - used);
}

fn print_results(results: &[HostResult], format: &Format) {
    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(results).unwrap_or_default());
        }
        Format::Csv => {
            println!("ip,status,mac,latency_ms,tcp_port,excluded");
            for r in results {
                println!(
                    "{},{},{},{},{},{}",
                    r.ip,
                    status_label(r.status),
                    r.mac.as_deref().unwrap_or(""),
                    r.latency_ms.map(|v| v.to_string()).unwrap_or_default(),
                    r.tcp_port.map(|v| v.to_string()).unwrap_or_default(),
                    r.excluded
                );
            }
        }
        Format::Table => {
            println!("{:<16} {:<8} {:<19} {:<9} {:<9} {}", "IP", "STATUS", "MAC", "LATENCY", "TCP", "EXCLUDED");
            for r in results {
                println!(
                    "{:<16} {:<8} {:<19} {:<9} {:<9} {}",
                    r.ip.to_string(),
                    status_label(r.status),
                    r.mac.as_deref().unwrap_or("-"),
                    r.latency_ms.map(|v| format!("{v}ms")).unwrap_or_else(|| "-".into()),
                    r.tcp_port.map(|v| format!(":{v}")).unwrap_or_else(|| "-".into()),
                    if r.excluded { "ya" } else { "-" }
                );
            }
        }
    }
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Used => "USED",
        Status::FreeCandidate => "FREE",
    }
}
