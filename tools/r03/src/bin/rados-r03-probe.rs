fn main() {
    if let Err(error) = rados_r03_tools::run_from_current_directory() {
        eprintln!("rados-r03-probe: {error}");
        std::process::exit(1);
    }
}
