//! The core's ares-status type.
//!
//! A newtype over the C status code so "an ares status" is distinct from the
//! other `i32`s around it (fds, families, timeout counts, masks). Pure and
//! safe; the ffi layer converts it back to `c_int` (`.code()`) at the C
//! boundary — it never crosses to C as `AresError`.
//!
//! Zero-cost: `repr(transparent)` guarantees identical layout to `c_int`, and
//! every conversion (`From`, `code`) inlines away in release builds.

use std::ffi::c_int;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AresError(c_int);

impl AresError {
    /// The underlying C status code — used only at the ffi boundary and for
    /// comparing against the `ARES_*` constants.
    pub(crate) fn code(self) -> c_int {
        self.0
    }
}

impl From<c_int> for AresError {
    fn from(code: c_int) -> Self {
        AresError(code)
    }
}
