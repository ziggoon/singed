use std::env;
use std::fs::File;
use std::io::Write;

fn get_sleep_time() -> u64 {
    match env::var("SLEEP") {
        Ok(val) => val.parse().unwrap_or(10),
        Err(_) => 10,
    }
}

fn get_ip() -> String {
    match env::var("IP") {
        Ok(val) => val,
        Err(_) => {
            eprintln!("fatal error: failed to read IP");
            std::process::exit(1);
        }
    }
}

fn get_port() -> u16 {
    match env::var("PORT") {
        Ok(val) => val.parse().unwrap_or(80),
        Err(_) => 80,
    }
}

fn main() {
    let sleep_time = get_sleep_time();
    let ip = get_ip();
    let port = get_port();

    let mut file = File::create("src/config.rs").unwrap();
    writeln!(file, "pub const SLEEP_TIME: u64 = {};", sleep_time).unwrap();
    writeln!(file, "pub const IP: &str = \"{}\";", ip).unwrap();
    writeln!(file, "pub const PORT: u16 = {};", port).unwrap();
}
