//! getnameinfo's pure parts: assembling the reply from a PTR answer
//! (NOFQDN, the numeric fallback, LOOKUPSERVICE), address formatting and
//! service-name/port mapping.

use std::ffi::CString;
use std::net::IpAddr;

use crate::core::response::ParsedResponse;
use crate::core::services::Services;
use crate::core::AresError;
use crate::ffi::error::{ARES_EBADSTR, ARES_ENOTFOUND, ARES_SUCCESS};
use crate::ffi::{
    ARES_NI_DGRAM, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NOFQDN, ARES_NI_NUMERICSCOPE, ARES_NI_NUMERICSERV,
    RECORD_TYPE_PTR,
};

/// Everything getnameinfo's PTR delivery needs: NOFQDN truncation, the
/// ENOTFOUND+!NAMEREQD numeric fallback, and the LOOKUPSERVICE gate.
pub(crate) struct NameinfoReply {
    pub status: AresError,
    pub node: Option<CString>,
    pub service: Option<CString>,
    pub timeouts: i32,
}

pub(crate) fn assemble_nameinfo(
    res: Result<&[u8], AresError>,
    ip: IpAddr,
    scope_id: u32,
    port: u16,
    flags: i32,
    io_timeouts: i32,
) -> NameinfoReply {
    let services = Services::default();
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    let hostname_result = (|| -> Result<CString, AresError> {
        let buf = res?;
        let parsed = ParsedResponse::from_buf(buf)?;
        let ptr_records = parsed.process_answers::<CString>(buf, RECORD_TYPE_PTR)?;

        if ptr_records.aliases.is_empty() {
            return Err(ARES_ENOTFOUND.into());
        }

        let mut name = ptr_records.name;

        if flags & ARES_NI_NOFQDN != 0 {
            let name_str = name.to_string_lossy();
            if let Some(dot_pos) = name_str.find('.') {
                name = CString::new(&name_str[..dot_pos]).map_err(|_| AresError::from(ARES_EBADSTR))?;
            }
        }

        Ok(name)
    })();

    let (status, node): (AresError, _) = match hostname_result {
        Ok(name) => (ARES_SUCCESS.into(), Some(name)),
        Err(err) => {
            if err.code() == ARES_ENOTFOUND && (flags & ARES_NI_NAMEREQD) == 0 {
                let ip_str = format_ip_with_scope(&ip, scope_id, flags);
                match CString::new(ip_str) {
                    Ok(name) => (ARES_SUCCESS.into(), Some(name)),
                    Err(_) => return NameinfoReply { status: ARES_EBADSTR.into(), node: None, service: None, timeouts: 0 },
                }
            } else {
                return NameinfoReply { status: err, node: None, service: None, timeouts: 0 };
            }
        }
    };

    let service = if want_service {
        get_service_string(&services, port, flags)
    } else {
        None
    };

    NameinfoReply { status, node, service, timeouts: io_timeouts }
}

pub(crate) fn format_ip_with_scope(ip: &IpAddr, scope_id: u32, flags: i32) -> String {
    match ip {
        // The scope id is appended regardless of the flag/scope_id check; the
        // branches are intentionally identical.
        #[allow(clippy::if_same_then_else)]
        IpAddr::V6(_) => {
            if flags & ARES_NI_NUMERICSCOPE != 0 || scope_id != 0 {
                format!("{}%{}", ip, scope_id)
            } else {
                format!("{}%{}", ip, scope_id)
            }
        }
        IpAddr::V4(_) => ip.to_string(),
    }
}

pub(crate) fn get_service_string(services: &Services, port: u16, flags: i32) -> Option<CString> {
    if port == 0 {
        return None;
    }

    // A numeric port string never contains NUL, so this is always `Some`.
    let numeric = || CString::new(port.to_string()).ok();

    if flags & ARES_NI_NUMERICSERV != 0 {
        return numeric();
    }

    let prefer_udp = (flags & ARES_NI_DGRAM) != 0;

    // Fall back to numeric (also when a service name has an embedded NUL).
    services
        .lookup_any(port, prefer_udp)
        .and_then(|name| CString::new(name).ok())
        .or_else(numeric)
}

/// How a getaddrinfo service string resolves to a port.
pub(crate) enum ServicePort {
    Port(u16),
    /// Not numeric and not in the well-known table: the shim asks the system
    /// resolver (getservbyname), defaulting to 0.
    NeedSystemLookup,
}

pub(crate) fn service_to_port(svc: &str) -> ServicePort {
    if let Ok(p) = svc.parse::<u16>() {
        return ServicePort::Port(p);
    }
    if let Some(p) = well_known_port(svc) {
        return ServicePort::Port(p);
    }
    ServicePort::NeedSystemLookup
}

/// The well-known service table consulted before libc::getservbyname.
fn well_known_port(svc: &str) -> Option<u16> {
    Some(match svc {
        "http" => 80,
        "https" => 443,
        "ftp" => 21,
        "ssh" => 22,
        "smtp" => 25,
        "dns" => 53,
        "pop3" => 110,
        "imap" => 143,
        _ => return None,
    })
}

/// A decoded socket address for getnameinfo.
pub(crate) struct AddrInfo {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) scope_id: u32,
}
