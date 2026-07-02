//! Channel-coupled safe kernels: the decision-making bodies of ares_*
//! exports that operate on `ChannelData`. Everything here is compiler-
//! enforced safe — storing raw pointers and C fn pointers is fine, only the
//! shims in the sibling ffi modules dereference or invoke them. Shims marshal
//! C arguments in, call one kernel, and marshal the verdict back out.
#![forbid(unsafe_code)]

pub(crate) mod channel;
pub(crate) mod lookups;
pub(crate) mod options;
