fn main() {
    if let Err(error) = rados_r02_tools::run_from_current_directory() {
        eprintln!("rados-r02-probe: {error}");
        std::process::exit(1);
    }
}
