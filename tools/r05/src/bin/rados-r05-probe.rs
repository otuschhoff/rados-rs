fn main() {
    if let Err(error) = rados_r05_tools::run_from_current_directory() {
        eprintln!("rados-r05-probe: {error}");
        std::process::exit(1);
    }
}
