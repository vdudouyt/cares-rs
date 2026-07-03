//! ares_addrinfo structures, list builders and ares_freeaddrinfo.

use super::*;


#[repr(C)]
pub struct ares_addrinfo_hints {
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
}

#[repr(C)]
pub struct ares_addrinfo_node {
    pub ai_ttl: c_int,
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen: libc::socklen_t,
    pub ai_addr: *mut libc::sockaddr,
    pub ai_next: *mut ares_addrinfo_node,
}

#[repr(C)]
pub struct ares_addrinfo_cname {
    pub ttl: c_int,
    pub alias: *mut c_char,
    pub name: *mut c_char,
    pub next: *mut ares_addrinfo_cname,
}

#[repr(C)]
pub struct ares_addrinfo {
    pub cnames: *mut ares_addrinfo_cname,
    pub nodes: *mut ares_addrinfo_node,
    pub name: *mut c_char,
}

/// Build the C node list for a synchronous (IP-literal / hosts-file)
/// delivery — pure transcription: the family filter was already applied in
/// core (api::getaddrinfo's DeliverAddrs arm).
pub(crate) fn addrinfo_nodes_from_addrs_port(addrs: &[IpAddr], port: u16) -> *mut ares_addrinfo_node {
    let mut head: *mut ares_addrinfo_node = std::ptr::null_mut();
    let mut tail: *mut ares_addrinfo_node = std::ptr::null_mut();
    for ip in addrs {
        let (ai_family, ai_addrlen, ai_addr): (c_int, libc::socklen_t, *mut libc::sockaddr) = match ip {
            IpAddr::V4(v4) => {
                let sa = Box::new(libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: port.to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.octets()) },
                    sin_zero: [0; 8],
                });
                (libc::AF_INET, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                 Box::into_raw(sa) as *mut libc::sockaddr)
            }
            IpAddr::V6(v6) => {
                let sa = Box::new(libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                    sin6_scope_id: 0,
                });
                (libc::AF_INET6, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                 Box::into_raw(sa) as *mut libc::sockaddr)
            }
        };
        let node = Box::into_raw(Box::new(ares_addrinfo_node {
            ai_ttl: 0,
            ai_flags: 0,
            ai_family,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen,
            ai_addr,
            ai_next: std::ptr::null_mut(),
        }));
        if head.is_null() {
            head = node;
        } else {
            unsafe { (*tail).ai_next = node };
        }
        tail = node;
    }
    head
}

/// Build the C node list from accumulated (safe) AddrRecords at delivery
/// time — arrival order preserved, ai_ttl carried from the answer records.
pub(crate) fn nodes_from_addr_records(records: &[AddrRecord], port: u16) -> *mut ares_addrinfo_node {
    let mut head: *mut ares_addrinfo_node = std::ptr::null_mut();
    let mut tail: *mut ares_addrinfo_node = std::ptr::null_mut();
    for record in records {
        let (ai_family, ai_addrlen, ai_addr): (c_int, libc::socklen_t, *mut libc::sockaddr) = match record.ip {
            IpAddr::V4(v4) => {
                let sa = Box::new(libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: port.to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.octets()) },
                    sin_zero: [0; 8],
                });
                (libc::AF_INET, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                 Box::into_raw(sa) as *mut libc::sockaddr)
            }
            IpAddr::V6(v6) => {
                let sa = Box::new(libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                    sin6_scope_id: 0,
                });
                (libc::AF_INET6, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                 Box::into_raw(sa) as *mut libc::sockaddr)
            }
        };
        let node = Box::into_raw(Box::new(ares_addrinfo_node {
            ai_ttl: record.ttl as c_int,
            ai_flags: 0,
            ai_family,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen,
            ai_addr,
            ai_next: std::ptr::null_mut(),
        }));
        if head.is_null() {
            head = node;
        } else {
            unsafe { (*tail).ai_next = node };
        }
        tail = node;
    }
    head
}

pub(crate) fn build_ares_addrinfo(name: &str, nodes: *mut ares_addrinfo_node) -> *mut ares_addrinfo {
    Box::into_raw(Box::new(ares_addrinfo {
        cnames: std::ptr::null_mut(),
        nodes,
        name: CString::new(name).unwrap_or_default().into_raw(),
    }))
}

pub(crate) unsafe fn free_addrinfo_nodes(mut node: *mut ares_addrinfo_node) {
    while !node.is_null() {
        let next = (unsafe { &*node }).ai_next;
        if !(unsafe { &*node }).ai_addr.is_null() {
            match (unsafe { &*node }).ai_family {
                libc::AF_INET => { drop(unsafe { Box::from_raw((*node).ai_addr as *mut libc::sockaddr_in) }); }
                libc::AF_INET6 => { drop(unsafe { Box::from_raw((*node).ai_addr as *mut libc::sockaddr_in6) }); }
                _ => {}
            }
        }
        unsafe { drop(Box::from_raw(node)) };
        node = next;
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_freeaddrinfo(ai: *mut ares_addrinfo) {
    if ai.is_null() { return; }
    let ai = unsafe { Box::from_raw(ai) };

    // Free nodes
    unsafe { free_addrinfo_nodes(ai.nodes) };

    // Free cnames
    let mut cname = ai.cnames;
    while !cname.is_null() {
        let next = unsafe { (*cname).next };
        if !unsafe { (*cname).alias }.is_null() {
            drop(unsafe { CString::from_raw((*cname).alias) });
        }
        if !unsafe { (*cname).name }.is_null() {
            drop(unsafe { CString::from_raw((*cname).name) });
        }
        drop(unsafe { Box::from_raw(cname) });
        cname = next;
    }

    // Free name
    if !ai.name.is_null() {
        drop(unsafe { CString::from_raw(ai.name) });
    }
}
