//! Library-local allocation. Never installs a process-wide Rust allocator.
//!
//! `CaresAllocator` routes vectors, strings, boxes, hash tables and shared
//! pointers through the callbacks registered by `ares_library_init_mem`.
//! Rust-owned blocks remember their callbacks, so an allocation is always freed
//! with the matching free function. Raw C buffers use the registered
//! malloc/free pair directly, including caller-allocated options arrays.
//!
//! Most resolver code uses the infallible `Vec`/`String`/`Rc` types. The C API
//! uses `FallibleVec`/`FallibleString`/`boxed` where allocation failure must
//! become `ARES_ENOMEM` instead of aborting.
use std::alloc::{AllocError, Allocator, AllocatorClone, Layout};
use std::ffi::c_void;
use std::ptr::{self, NonNull};
use std::sync::Mutex;

mod task;
mod waker;
mod containers;
pub(crate) use containers::{HashMap, HashSet};
pub(crate) use task::Task;
pub(crate) use waker::ReadyFlag;

pub(crate) type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
pub(crate) type Free = unsafe extern "C" fn(*mut c_void);
pub(crate) type Realloc = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;

#[derive(Clone, Copy)]
struct Hooks { malloc: Malloc, free: Free, realloc: Realloc }
const SYSTEM: Hooks = Hooks { malloc: libc::malloc, free: libc::free, realloc: libc::realloc };
static LIBRARY: Mutex<(usize, Hooks)> = Mutex::new((0, SYSTEM));

fn hooks() -> Hooks { LIBRARY.lock().unwrap_or_else(std::sync::PoisonError::into_inner).1 }

pub(crate) fn init(malloc: Option<Malloc>, free: Option<Free>, realloc: Option<Realloc>) {
    let mut state = LIBRARY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(f) = malloc { state.1.malloc = f; }
    if let Some(f) = free { state.1.free = f; }
    if let Some(f) = realloc { state.1.realloc = f; }
    state.0 = state.0.saturating_add(1);
}

pub(crate) fn cleanup() {
    let mut state = LIBRARY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.0 != 0 {
        state.0 -= 1;
        if state.0 == 0 { state.1 = SYSTEM; }
    }
}

#[derive(Clone, Copy)]
struct Header { base: *mut u8, hooks: Hooks }

// Header alignment also makes all header reads/writes aligned, even for bytes.
fn allocation_layout(layout: Layout) -> Result<(Layout, usize), AllocError> {
    let align = layout.align().max(align_of::<Header>());
    let size = layout.size().checked_add(size_of::<Header>())
        .and_then(|n| n.checked_add(align - 1)).ok_or(AllocError)?;
    Ok((Layout::from_size_align(size, align).map_err(|_| AllocError)?, align))
}

unsafe fn install_header(base: NonNull<u8>, align: usize, hooks: Hooks) -> NonNull<u8> {
    let start = unsafe { base.as_ptr().add(size_of::<Header>()) };
    let data = unsafe { start.add(start.align_offset(align)) };
    unsafe { data.cast::<Header>().sub(1).write(Header { base: base.as_ptr(), hooks }) };
    // data lies in the non-null allocation, after its header.
    unsafe { NonNull::new_unchecked(data) }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CaresAllocator;

// SAFETY: blocks carry their owning allocator; all instances are equivalent.
// Allocation errors leave existing storage intact. No callback is invoked while
// the library-state mutex is held (callbacks can reenter the library).
unsafe impl AllocatorClone for CaresAllocator {}

unsafe impl Allocator for CaresAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let (total, align) = allocation_layout(layout)?;
        let hooks = hooks();
        let base = NonNull::new(unsafe { (hooks.malloc)(total.size()).cast::<u8>() }).ok_or(AllocError)?;
        let data = unsafe { install_header(base, align, hooks) };
        Ok(NonNull::slice_from_raw_parts(data, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _: Layout) {
        let header = unsafe { ptr.as_ptr().cast::<Header>().sub(1).read() };
        unsafe { (header.hooks.free)(header.base.cast()) };
    }

    unsafe fn grow(&self, ptr: NonNull<u8>, old: Layout, new: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let header = unsafe { ptr.as_ptr().cast::<Header>().sub(1).read() };
        let offset = unsafe { ptr.as_ptr().offset_from(header.base) } as usize;
        let (total, align) = allocation_layout(new)?;
        // Preserve the old payload even if the new alignment is smaller.
        let size = total.size().max(offset.checked_add(old.size()).ok_or(AllocError)?);
        if size > isize::MAX as usize { return Err(AllocError); }
        let base = NonNull::new(unsafe { (header.hooks.realloc)(header.base.cast(), size).cast::<u8>() })
            .ok_or(AllocError)?;
        let start = unsafe { base.as_ptr().add(size_of::<Header>()) };
        let data = unsafe { start.add(start.align_offset(align)) };
        // Realloc may move the block, changing its alignment padding. Move the
        // payload before installing the header, which can overlap its old bytes.
        unsafe { ptr::copy(base.as_ptr().add(offset), data, old.size()) };
        let data = unsafe { install_header(base, align, header.hooks) };
        Ok(NonNull::slice_from_raw_parts(data, new.size()))
    }
}

pub(crate) fn malloc(size: usize) -> *mut c_void {
    if size == 0 || size > isize::MAX as usize { return ptr::null_mut(); }
    unsafe { (hooks().malloc)(size) }
}

/// `ptr` is null or a live C allocation compatible with the registered free
/// callback. As upstream, exported C buffers must be freed before cleanup.
pub(crate) unsafe fn free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { (hooks().free)(ptr) };
    }
}

pub(crate) type Owned<T> = Box<T, CaresAllocator>;
pub type Rc<T> = std::rc::Rc<T, CaresAllocator>;
pub type Weak<T> = std::rc::Weak<T, CaresAllocator>;

pub fn rc<T>(value: T) -> Rc<T> { Rc::new_in(value, CaresAllocator) }

/// Box value like std's `Box::new`; allocation failure aborts.
pub(crate) fn boxed_infallible<T>(value: T) -> Owned<T> {
    Box::new_in(value, CaresAllocator)
}

pub(crate) fn boxed<T>(value: T) -> Result<Owned<T>, NoMemory> {
    let ptr = if size_of::<T>() == 0 { NonNull::dangling() } else {
        CaresAllocator.allocate(Layout::new::<T>()).map_err(|_| NoMemory)?.cast::<T>()
    };
    unsafe {
        ptr.as_ptr().write(value);
        Ok(Box::from_raw_in(ptr.as_ptr(), CaresAllocator))
    }
}

/// Initialize already-admitted storage without moving a callback into a
/// fallible operation. Dropping uninitialized storage never drops a T.
pub(crate) fn initialize<T>(storage: Owned<std::mem::MaybeUninit<T>>, value: T) -> Owned<T> {
    let ptr = Box::leak(storage).write(value) as *mut T;
    unsafe { Box::from_raw_in(ptr, CaresAllocator) }
}

/// Transfer a Box to an owning C handle. Pair with `drop_box`, never libc::free.
pub(crate) fn into_raw<T: ?Sized>(value: Owned<T>) -> *mut T { Box::leak(value) }

/// `ptr` is null or an owning pointer previously returned by `into_raw`.
pub(crate) unsafe fn from_raw<T: ?Sized>(ptr: *mut T) -> Owned<T> {
    // SAFETY: the caller passes a pointer from into_raw.
    unsafe { Box::from_raw_in(ptr, CaresAllocator) }
}

/// `ptr` is null or an owning pointer previously returned by `into_raw`.
pub(crate) unsafe fn drop_box<T: ?Sized>(ptr: *mut T) {
    if !ptr.is_null() { drop(unsafe { Box::from_raw_in(ptr, CaresAllocator) }); }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NoMemory;

impl From<NoMemory> for crate::core::AresError {
    fn from(_: NoMemory) -> Self { crate::ffi::error::ARES_ENOMEM.into() }
}
impl From<NoMemory> for i32 {
    fn from(_: NoMemory) -> Self { crate::ffi::error::ARES_ENOMEM }
}
impl From<NoMemory> for std::io::Error {
    fn from(_: NoMemory) -> Self { std::io::ErrorKind::OutOfMemory.into() }
}

/// A vector for operations that must report allocation failure to C callers.
/// Only fallible growth is exposed.
#[derive(Debug)]
pub(crate) struct FallibleVec<T>(std::vec::Vec<T, CaresAllocator>);
impl<T> Default for FallibleVec<T> { fn default() -> Self { Self::new() } }
impl<T> FallibleVec<T> {
    pub(crate) fn new() -> Self { Self(std::vec::Vec::new_in(CaresAllocator)) }
    pub(crate) fn reserve(&mut self, n: usize) -> Result<(), NoMemory> {
        self.0.try_reserve(n).map_err(|_| NoMemory)
    }
    pub(crate) fn push(&mut self, value: T) -> Result<(), NoMemory> {
        self.reserve(1)?;
        self.0.push(value);
        Ok(())
    }
    pub(crate) fn extend_from_slice(&mut self, data: &[T]) -> Result<(), NoMemory> where T: Copy {
        self.reserve(data.len())?;
        self.0.extend_from_slice(data);
        Ok(())
    }
    pub(crate) fn copy_from(data: &[T]) -> Result<Self, NoMemory> where T: Copy {
        let mut out = Self::new();
        out.extend_from_slice(data)?;
        Ok(out)
    }
    pub(crate) fn swap_remove(&mut self, index: usize) -> T { self.0.swap_remove(index) }
    pub(crate) fn remove(&mut self, index: usize) -> T { self.0.remove(index) }
    pub(crate) fn retain(&mut self, f: impl FnMut(&T) -> bool) { self.0.retain(f); }
    pub(crate) fn as_slice(&self) -> &[T] { &self.0 }
}
impl<T> std::ops::Deref for FallibleVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] { &self.0 }
}
impl<T> std::ops::DerefMut for FallibleVec<T> { fn deref_mut(&mut self) -> &mut [T] { &mut self.0 } }
impl<T> IntoIterator for FallibleVec<T> {
    type Item = T;
    type IntoIter = <std::vec::Vec<T, CaresAllocator> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}
impl<'a, T> IntoIterator for &'a FallibleVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter { self.iter() }
}
impl<'a, T> IntoIterator for &'a mut FallibleVec<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter { self.iter_mut() }
}

/// Ordinary collections use the c-ares callbacks without fallible plumbing.
/// Like std's containers, an allocation failure aborts the process.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Vec<T>(std::vec::Vec<T, CaresAllocator>);
impl<T> Default for Vec<T> { fn default() -> Self { Self::new() } }
impl<T> Vec<T> {
    pub(crate) fn new() -> Self { Self(std::vec::Vec::new_in(CaresAllocator)) }
    pub(crate) fn with_capacity(n: usize) -> Self { Self(std::vec::Vec::with_capacity_in(n, CaresAllocator)) }
    pub(crate) fn from_slice(data: &[T]) -> Self where T: Clone {
        let mut out = Self::with_capacity(data.len());
        out.0.extend_from_slice(data);
        out
    }
    pub(crate) fn into_boxed_slice(self) -> Owned<[T]> { self.0.into_boxed_slice() }
    /// Reclaim storage produced by `into_boxed_slice`/`into_raw` plus
    /// `std::mem::forget`, e.g. a C null-terminated array.
    pub(crate) unsafe fn from_raw_parts(ptr: *mut T, len: usize, capacity: usize) -> Self {
        Self(unsafe { std::vec::Vec::from_raw_parts_in(ptr, len, capacity, CaresAllocator) })
    }
}
impl<T> std::ops::Deref for Vec<T> {
    type Target = std::vec::Vec<T, CaresAllocator>;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl<T> std::ops::DerefMut for Vec<T> { fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 } }
impl<T> AsRef<[T]> for Vec<T> { fn as_ref(&self) -> &[T] { self } }
impl<T> std::borrow::Borrow<[T]> for Vec<T> { fn borrow(&self) -> &[T] { self } }
impl<T> FromIterator<T> for Vec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut out = Self::new();
        out.extend(iter);
        out
    }
}
impl<T> Extend<T> for Vec<T> { fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) { self.0.extend(iter); } }
impl<T> IntoIterator for Vec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T, CaresAllocator>;
    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}
impl<'a, T> IntoIterator for &'a Vec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter { self.iter() }
}
impl<'a, T> IntoIterator for &'a mut Vec<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter { self.iter_mut() }
}
impl<T: Clone> From<&[T]> for Vec<T> { fn from(data: &[T]) -> Self { Self::from_slice(data) } }
impl<T, const N: usize> From<[T; N]> for Vec<T> { fn from(data: [T; N]) -> Self { data.into_iter().collect() } }
impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for Vec<T> {
    fn eq(&self, other: &[T; N]) -> bool { self.as_slice() == other }
}
impl<T: PartialEq, const N: usize> PartialEq<&[T; N]> for Vec<T> {
    fn eq(&self, other: &&[T; N]) -> bool { self.as_slice() == **other }
}
impl<T: PartialEq> PartialEq<&[T]> for Vec<T> {
    fn eq(&self, other: &&[T]) -> bool { self.as_slice() == *other }
}
impl<T: PartialEq> PartialEq<std::vec::Vec<T>> for Vec<T> {
    fn eq(&self, other: &std::vec::Vec<T>) -> bool { self.as_slice() == other }
}

/// DNS wire buffers use the same callback-backed storage as every other
/// container.
pub(crate) type ByteBuf = Vec<u8>;

/// Byte-buffer writes for DNS serialization.
#[allow(dead_code)] // The full trait is used by the packet tests.
pub(crate) trait BufMut {
    fn put_u8(&mut self, value: u8);
    fn put_u16(&mut self, value: u16);
    fn put_slice(&mut self, bytes: &[u8]);
}
impl BufMut for Vec<u8> {
    fn put_u8(&mut self, value: u8) { self.push(value); }
    fn put_u16(&mut self, value: u16) { self.extend_from_slice(&value.to_be_bytes()); }
    fn put_slice(&mut self, bytes: &[u8]) { self.extend_from_slice(bytes); }
}

#[derive(Debug, Default)]
pub(crate) struct FallibleString(FallibleVec<u8>);
impl FallibleString {
    pub(crate) fn new() -> Self { Self(FallibleVec::new()) }
    pub(crate) fn push_str(&mut self, s: &str) -> Result<(), NoMemory> { self.0.extend_from_slice(s.as_bytes()) }
    pub(crate) fn push_lossy(&mut self, bytes: &[u8]) -> Result<(), NoMemory> {
        for chunk in bytes.utf8_chunks() {
            self.push_str(chunk.valid())?;
            if !chunk.invalid().is_empty() { self.push_str("\u{fffd}")?; }
        }
        Ok(())
    }
}
impl std::ops::Deref for FallibleString {
    type Target = str;
    fn deref(&self) -> &str {
        // All construction and mutation accepts valid UTF-8 only.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}
impl std::fmt::Write for FallibleString {
    fn write_str(&mut self, s: &str) -> std::fmt::Result { self.push_str(s).map_err(|_| std::fmt::Error) }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct String(Vec<u8>);
impl String {
    pub(crate) fn new() -> Self { Self(Vec::new()) }
    pub(crate) fn as_str(&self) -> &str { self }
    pub(crate) fn push_str(&mut self, s: &str) { self.0.extend_from_slice(s.as_bytes()); }
    pub(crate) fn push(&mut self, ch: char) { self.push_str(ch.encode_utf8(&mut [0; 4])); }
    pub(crate) fn from_utf8_lossy(bytes: &[u8]) -> Self {
        let mut out = Self::new();
        for chunk in bytes.utf8_chunks() {
            out.push_str(chunk.valid());
            if !chunk.invalid().is_empty() { out.push_str("\u{fffd}"); }
        }
        out
    }
}
impl std::ops::Deref for String {
    type Target = str;
    fn deref(&self) -> &str {
        // All construction and mutation accepts valid UTF-8 only.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}
impl std::fmt::Debug for String {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Debug::fmt(&**self, f) }
}
impl std::fmt::Display for String { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self) } }
impl std::fmt::Write for String {
    fn write_str(&mut self, s: &str) -> std::fmt::Result { self.push_str(s); Ok(()) }
}
impl AsRef<str> for String { fn as_ref(&self) -> &str { self } }
impl AsRef<[u8]> for String { fn as_ref(&self) -> &[u8] { self.as_bytes() } }
impl AsRef<std::path::Path> for String { fn as_ref(&self) -> &std::path::Path { std::path::Path::new(self.as_str()) } }
impl FromIterator<char> for String {
    fn from_iter<I: IntoIterator<Item = char>>(iter: I) -> Self {
        let mut out = Self::new();
        for ch in iter { out.push(ch); }
        out
    }
}
impl std::borrow::Borrow<str> for String { fn borrow(&self) -> &str { self } }
impl From<&str> for String { fn from(s: &str) -> Self { let mut out = Self::new(); out.push_str(s); out } }
impl PartialEq<str> for String { fn eq(&self, other: &str) -> bool { &**self == other } }
impl PartialEq<&str> for String { fn eq(&self, other: &&str) -> bool { &**self == *other } }

/// `vec!` for allocator-backed vectors (mainly convenient in tests).
#[cfg(test)]
macro_rules! vec {
    () => { $crate::mem::Vec::new() };
    ($value:expr; $count:expr) => {{
        let mut out = $crate::mem::Vec::new();
        out.resize($count, $value);
        out
    }};
    ($($value:expr),+ $(,)?) => { $crate::mem::Vec::from([$($value),+]) };
}
#[cfg(test)]
pub(crate) use vec;

pub(crate) fn join<S: AsRef<str>>(parts: &[S], separator: &str) -> String {
    let mut out = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i != 0 { out.push_str(separator); }
        out.push_str(part.as_ref());
    }
    out
}

#[derive(Debug)]
pub(crate) struct CString { ptr: NonNull<u8>, len: usize, free: Free }
impl CString {
    pub(crate) fn from_string(s: FallibleString) -> Result<Self, crate::core::AresError> {
        Self::new(s.as_bytes())
    }
    pub(crate) fn new(bytes: impl AsRef<[u8]>) -> Result<Self, crate::core::AresError> {
        let bytes = bytes.as_ref();
        if bytes.contains(&0) { return Err(crate::ffi::error::ARES_EBADRESP.into()); }
        let len = bytes.len();
        let size = len.checked_add(1).filter(|&n| n <= isize::MAX as usize).ok_or(NoMemory)?;
        let hooks = hooks();
        let ptr = NonNull::new(unsafe { (hooks.malloc)(size).cast::<u8>() }).ok_or(NoMemory)?;
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.as_ptr(), len);
            ptr.as_ptr().add(len).write(0);
        }
        Ok(Self { ptr, len, free: hooks.free })
    }
    pub(crate) fn as_c_str(&self) -> &std::ffi::CStr { self }
    pub(crate) fn as_bytes(&self) -> &[u8] { self.to_bytes() }
    pub(crate) fn into_raw(self) -> *mut std::ffi::c_char {
        // Raw C ownership obeys the library-init lifetime, like upstream.
        std::mem::ManuallyDrop::new(self).ptr.as_ptr().cast()
    }
    /// Reclaim a pointer produced by [`CString::into_raw`]. As upstream, the
    /// caller must free it before `ares_library_cleanup` restores the defaults.
    pub(crate) unsafe fn from_raw(ptr: *mut std::ffi::c_char) -> Self {
        // SAFETY: the caller passes a live CString produced by into_raw.
        let bytes = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_bytes();
        let free = hooks().free;
        // SAFETY: checked by the caller and asserted above.
        Self { ptr: unsafe { NonNull::new_unchecked(ptr) }.cast(), len: bytes.len(), free }
    }
}
impl std::ops::Deref for CString {
    type Target = std::ffi::CStr;
    fn deref(&self) -> &Self::Target {
        // Construction guarantees exactly one trailing NUL.
        unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(self.ptr.as_ptr(), self.len + 1)) }
    }
}
impl Default for CString {
    fn default() -> Self {
        match Self::new([]) {
            Ok(empty) => empty,
            Err(_) => std::process::abort(),
        }
    }
}
impl Clone for CString {
    fn clone(&self) -> Self {
        // A live CString is NUL-free, so only allocation can fail.
        match Self::new(self.as_bytes()) {
            Ok(copy) => copy,
            Err(_) => std::process::abort(),
        }
    }
}
impl Drop for CString {
    fn drop(&mut self) { unsafe { (self.free)(self.ptr.as_ptr().cast()) }; }
}
