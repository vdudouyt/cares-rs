use std::ffi::{ c_void, c_int, CString };
use std::io::Cursor;
use crate::ffi::null_terminated;
use crate::core::packets::*;
use crate::{ ARES_ENODATA, ARES_EFORMERR };

#[derive(PartialEq)]
pub enum HostentParseMode { Addrs, Addrs4, Addrs6, Aliases }

pub unsafe fn parse_hostent(abuf: *const u8, alen: c_int, mode: HostentParseMode) -> Result<libc::hostent, i32> {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let frame = DnsFrame::parse(&mut Cursor::new(buf)).unwrap();

    let Some(answer) = frame.answers.first() else { return Err(ARES_ENODATA) };
    let name = answer.name.build_cstring(&buf).unwrap();
    let h_addrtype = match answer.record_type {
        0x01 => libc::AF_INET,
        0x1c => libc::AF_INET6,
        0x02 => 0x02,
        _ => panic!("Unexpected DNS record type in answer: {}", answer.record_type),
    };

    let mut aliases: Vec<*mut i8> = vec![];
    let mut addr_list: Vec<*mut i8> = vec![];
    match mode {
        HostentParseMode::Addrs | HostentParseMode::Addrs4 | HostentParseMode::Addrs6 => for answer in &frame.answers {
            if mode == HostentParseMode::Addrs4 && h_addrtype != libc::AF_INET {
                continue;
            }
            if mode == HostentParseMode::Addrs6 && h_addrtype != libc::AF_INET6 {
                continue;
            }
            let expected_length = match h_addrtype {
                libc::AF_INET => 4,
                libc::AF_INET6 => 16,
                _ => return Err(ARES_EFORMERR),
            };
            if answer.data.len() != expected_length {
                return Err(ARES_EFORMERR);
            }
            let dst = unsafe { libc::malloc(answer.data.len()) } as *mut u8;
            unsafe { std::ptr::copy_nonoverlapping(answer.data.as_ptr(), dst, answer.data.len()) };
            addr_list.push(dst as *mut i8);
        },
        HostentParseMode::Aliases => for answer in &frame.answers {
            let label = DnsLabel::parse(&mut Cursor::new(&answer.data)).unwrap();
            let alias = label.build_cstring(&buf).unwrap();
            aliases.push(alias.into_raw());
        },
    }

    let ret = libc::hostent {
        h_name: name.into_raw(),
        h_aliases: unsafe { null_terminated::from_vec(aliases) },
        h_addrtype,
        h_length: answer.data.len() as i32,
        h_addr_list:  unsafe { null_terminated::from_vec(addr_list) },
    };
    Ok(ret)
}

pub unsafe fn free_hostent(hostent: *mut libc::hostent) {
    unsafe {
        let hostent = Box::from_raw(hostent);
        drop(CString::from_raw(hostent.h_name));
        let vec = null_terminated::into_vec(hostent.h_aliases);
        for v in vec { drop(CString::from_raw(v)); }
        let vec = null_terminated::into_vec(hostent.h_addr_list);
        for v in vec { libc::free(v as *mut c_void) }
    }
}
