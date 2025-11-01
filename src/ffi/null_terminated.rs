use std::ptr;

pub unsafe fn from_vec<T>(mut v: Vec<T>, sentinel: T) -> *mut T
where
    T: Copy + PartialEq,
{
    v.push(sentinel);
    let boxed: Box<[T]> = v.into_boxed_slice();
    Box::into_raw(boxed) as *mut T
}

pub unsafe fn into_vec<T>(ptr: *mut T, sentinel: T) -> Vec<T>
where T: Copy + PartialEq
{
    if ptr.is_null() { return Vec::new() }

    let mut len = 0usize;
    loop {
        let val = unsafe { ptr::read(ptr.add(len)) };
        len += 1;
        if val == sentinel {
            break;
        }
    }

    let mut v = unsafe { Vec::from_raw_parts(ptr, len, len) };
    v.pop(); // drop sentinel
    v
}




