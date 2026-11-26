//! A newtype over the C status code, so an ares status is distinct from other
//! `i32`s (fds, families, masks). `repr(transparent)`: identical to `c_int`.

use std::ffi::c_int;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AresError(c_int);

impl AresError {
    /// The underlying C status code, used at the ffi boundary.
    pub(crate) fn code(self) -> c_int {
        self.0
    }
}

impl From<c_int> for AresError {
    fn from(code: c_int) -> Self {
        AresError(code)
    }
}
