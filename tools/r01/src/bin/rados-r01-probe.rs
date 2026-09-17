fn main() {
    if let Err(error) = rados_r01_tools::run_from_current_directory() {
        eprintln!("rados-r01-probe: {error}");
        std::process::exit(1);
    }
}
