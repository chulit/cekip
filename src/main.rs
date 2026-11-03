use cekip::{scan, Excludes, HostResult, Status, Target};
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
    }
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
