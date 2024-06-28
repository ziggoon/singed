use crate::commands::Command;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::str;
use std::io::Cursor;

#[derive(Debug)]
pub struct Serializer {
    buffer: Vec<u8>,
}


/*      PAYLOAD STRUCTURE
        [ SIZE         ] 4 bytes (i32)
        [ Magic Value  ] 4 bytes (str)
        [ Agent ID     ] 4 bytes (i32)
        [ COMMAND ID   ] 4 bytes (i32)
        [ Demon ID     ] 4 bytes (i32)
        [ User Name    ] size + bytes (str)
        [ Host Name    ] size + bytes (str)
        [ IP Address   ] 16 bytes? (str)
        [ Process Name ] size + bytes (str)
        [ Process ID   ] 4 bytes (i32)
        [ Parent  PID  ] 4 bytes (i32)
        [ Process Arch ] 4 bytes (str)
        [ Elevated     ] 4 bytes (i32)
        [ OS Info      ] ( 5 * 4 ) bytes (str)
    */

impl Serializer {
    // for serializing raw data i.e. responses from the server
    pub fn new(raw_buffer: &[u8]) -> Self {
        let serializer = Serializer { buffer: raw_buffer.to_vec() };
        
        return serializer
    }

    pub fn init(agent_id: i32, command_id: Command) -> Self {
        let mut serializer = Serializer { buffer: Vec::new() };
        
        // set payload len to 0
        serializer.add_int32(0);
        
        // add magic value 
        serializer.add_int32(1337);

        // add agent id
        serializer.add_int32(agent_id);

        // add command id
        serializer.add_int32(command_id as i32);

        return serializer
    }

    pub fn add_int32(&mut self, value: i32) {
        self.buffer.write_i32::<NetworkEndian>(value).unwrap();
    }

    pub fn add_string(&mut self, value: &str) {
        let len = value.len() as i32;
        self.add_int32(len as i32);
        self.buffer.extend_from_slice(value.as_bytes());
    }

    #[allow(dead_code)]
    pub fn add_data(&mut self, data: &[u8]) {
        self.add_int32(data.len() as i32);
        self.buffer.extend_from_slice(data);
    }

    #[allow(dead_code)]
    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }

    #[allow(dead_code)]
    pub fn get_int32(&mut self) -> i32 {
        let mut cursor = Cursor::new(&self.buffer);
        cursor.read_i32::<NetworkEndian>().unwrap()
    }
}
