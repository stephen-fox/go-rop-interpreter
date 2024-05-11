use std::fs::File;
use std::io::prelude::*;
use std::os::fd::FromRawFd;
use std::str;
use std::sync::mpsc;
use std::thread;

#[no_mangle]
pub fn testing(read_fd: i32, write_fd: i32) -> u8 {
    println!("read_fd {read_fd} | write_fd: {write_fd}");

    let mut read_pipe = unsafe { File::from_raw_fd(read_fd) };
    let mut write_pipe = unsafe { File::from_raw_fd(write_fd) };

    //let (send, recv) = mpsc::channel::<bool>();
    //let handle = thread::spawn(|| {});

    let mut buffer = [0; 100];

    let rn = match read_pipe.read(&mut buffer[..]) {
        Ok(num) => num,
        Err(_) => {
            return 1;
        }
    };

    let s = match str::from_utf8(&buffer) {
        Ok(v) => v,
        Err(_) => {
            return 3;
        }
    };

    println!("read done: {rn} | {s}");

    let wn = match write_pipe.write(&buffer[..rn]) {
        Ok(num) => num,
        Err(_) => {
            return 2;
        }
    };

    println!("write done {wn}");

    0
}
