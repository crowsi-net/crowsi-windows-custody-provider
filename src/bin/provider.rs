#[cfg(windows)]
fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if crowsi_windows_custody_provider::serve_one(stdin.lock(), stdout.lock()).is_err() {
        std::process::exit(70);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("crowsi-windows-custody-provider: windows-custody-backend-unavailable");
    std::process::exit(78);
}
