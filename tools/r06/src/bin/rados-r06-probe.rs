fn main() {
    if let Err(error) = rados_r06_tools::run_from_current_directory() {
        eprintln!("rados-r06-probe: {error}");
        std::process::exit(1);
    }
}
