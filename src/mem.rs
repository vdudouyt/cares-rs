//! Library-local allocation. Never installs a process-wide Rust allocator.
//!
//! Rust-owned blocks remember their callbacks. Raw C buffers use the registered
//! malloc/free pair directly, including caller-allocated options arrays.
use std::alloc::{AllocError, Allocator, Layout};
use std::ffi::c_void;
use std::ptr::{self, NonNull};
use std::sync::Mutex;

mod task;
mod waker;
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
pub(crate) struct CaresAllocator;

// SAFETY: blocks carry their owning allocator; all instances are equivalent.
// Allocation errors leave existing storage intact. No callback is invoked while
// the library-state mutex is held (callbacks can reenter the library).
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
pub(crate) fn into_raw<T>(value: Owned<T>) -> *mut T { Box::leak(value) }

/// `ptr` is null or an owning pointer previously returned by `into_raw`.
pub(crate) unsafe fn drop_box<T>(ptr: *mut T) {
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

/// Only fallible growth is exposed. Slice access cannot grow the allocation.
#[derive(Debug)]
pub(crate) struct Vec<T>(std::vec::Vec<T, CaresAllocator>);
impl<T> Default for Vec<T> { fn default() -> Self { Self::new() } }
impl<T> Vec<T> {
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
impl<T> std::ops::Deref for Vec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] { &self.0 }
}
impl<T> std::ops::DerefMut for Vec<T> { fn deref_mut(&mut self) -> &mut [T] { &mut self.0 } }
impl<T> IntoIterator for Vec<T> {
    type Item = T;
    type IntoIter = <std::vec::Vec<T, CaresAllocator> as IntoIterator>::IntoIter;
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

// hashbrown's stable allocator interface predates std's stabilization.
unsafe impl allocator_api2::alloc::Allocator for CaresAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        Allocator::allocate(self, layout).map_err(|_| allocator_api2::alloc::AllocError)
    }
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        unsafe { Allocator::deallocate(self, ptr, layout) };
    }
    unsafe fn grow(&self, ptr: NonNull<u8>, old: Layout, new: Layout) -> Result<NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        unsafe { Allocator::grow(self, ptr, old, new) }.map_err(|_| allocator_api2::alloc::AllocError)
    }
}

pub(crate) struct Map<K, V>(hashbrown::HashMap<K, V, std::hash::RandomState, CaresAllocator>);
impl<K: Eq + std::hash::Hash, V> Default for Map<K, V> { fn default() -> Self { Self::new() } }
impl<K: Eq + std::hash::Hash, V> Map<K, V> {
    pub(crate) fn new() -> Self {
        Self(hashbrown::HashMap::with_hasher_in(std::hash::RandomState::new(), CaresAllocator))
    }
    pub(crate) fn insert(&mut self, key: K, value: V) -> Result<(), NoMemory> {
        if let Some(slot) = self.0.get_mut(&key) { *slot = value; } else {
            self.0.try_reserve(1).map_err(|_| NoMemory)?;
            self.0.insert(key, value);
        }
        Ok(())
    }
    pub(crate) fn get(&self, key: &K) -> Option<&V> { self.0.get(key) }
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> { self.0.get_mut(key) }
    pub(crate) fn remove(&mut self, key: &K) -> Option<V> { self.0.remove(key) }
}

#[derive(Debug, Default)]
pub(crate) struct String(Vec<u8>);
impl String {
    pub(crate) fn new() -> Self { Self(Vec::new()) }
    pub(crate) fn push_str(&mut self, s: &str) -> Result<(), NoMemory> { self.0.extend_from_slice(s.as_bytes()) }
    pub(crate) fn push_lossy(&mut self, bytes: &[u8]) -> Result<(), NoMemory> {
        for chunk in bytes.utf8_chunks() {
            self.push_str(chunk.valid())?;
            if !chunk.invalid().is_empty() { self.push_str("\u{fffd}")?; }
        }
        Ok(())
    }
}
impl std::ops::Deref for String {
    type Target = str;
    fn deref(&self) -> &str {
        // All construction and mutation accepts valid UTF-8 only.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}
impl std::fmt::Write for String {
    fn write_str(&mut self, s: &str) -> std::fmt::Result { self.push_str(s).map_err(|_| std::fmt::Error) }
}

#[derive(Debug)]
pub(crate) struct CString { ptr: NonNull<u8>, len: usize, free: Free }
impl CString {
    pub(crate) fn from_string(s: String) -> Result<Self, crate::core::AresError> {
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
}
impl std::ops::Deref for CString {
    type Target = std::ffi::CStr;
    fn deref(&self) -> &Self::Target {
        // Construction guarantees exactly one trailing NUL.
        unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(self.ptr.as_ptr(), self.len + 1)) }
    }
}
impl Drop for CString {
    fn drop(&mut self) { unsafe { (self.free)(self.ptr.as_ptr().cast()) }; }
}
