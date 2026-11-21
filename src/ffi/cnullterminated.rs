use std::ptr;
use crate::mem::{into_raw, Vec};

pub trait Nullable {
    const NULL: Self;
}

impl<T> Nullable for *mut T {
    const NULL: Self = ptr::null_mut();
}

pub unsafe fn from_vec<T>(mut v: Vec<T>) -> *mut T
where
    T: Copy + PartialEq + Nullable,
{
    v.push(T::NULL);
    into_raw(v.into_boxed_slice()) as *mut T
}

pub unsafe fn into_vec<T>(ptr: *mut T) -> Vec<T>
where T: Copy + PartialEq + Nullable
{
    if ptr.is_null() { return Vec::new() }

    let mut len = 0usize;
    loop {
        let val = unsafe { ptr::read(ptr.add(len)) };
        len += 1;
        if val == T::NULL {
            break;
        }
    }

    let mut v = unsafe { Vec::from_raw_parts(ptr, len, len) };
    v.pop(); // drop sentinel
    v
}
