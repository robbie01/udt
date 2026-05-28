use std::io;

#[allow(dead_code)]
pub unsafe fn udt_strerror() -> String {
    unsafe { udt_sys::getlasterror_desc() }.to_string_lossy().into_owned()
}

pub unsafe fn udt_getlasterror() -> io::Error {
    let code = unsafe { udt_sys::getlasterror_code() };
    let kind = match code {
        udt_sys::EASYNCSND | udt_sys::EASYNCRCV => io::ErrorKind::WouldBlock,
        udt_sys::ENOSERVER => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other
    };
    
    if kind == io::ErrorKind::WouldBlock {
        kind.into()
    } else {
        io::Error::new(
            kind,
            unsafe { udt_strerror() }
        )
    }
}