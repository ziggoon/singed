use std::fs::OpenOptions;
use std::io::{self, Write};
use std::process;

pub fn clear_cmdline() -> io::Result<()> {
    let pid = process::id();

    let cmdline = format!("/proc/{}/cmdline", pid);

    let mut file = OpenOptions::new().write(true).truncate(true).open(cmdline)?;
    file.write_all(b"")?;

    Ok(())
}
