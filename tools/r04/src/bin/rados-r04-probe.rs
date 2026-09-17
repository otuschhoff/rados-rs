fn main() {
    if let Err(error) = rados_r04_tools::run_from_current_directory() {
        eprintln!("rados-r04-probe: {error}");
        std::process::exit(1);
    }
}
