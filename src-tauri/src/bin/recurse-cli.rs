fn main() {
    if let Err(e) = recurse_lib::cli::run() {
        eprintln!("[recurse-cli] error: {e}");
        std::process::exit(1);
    }
}
