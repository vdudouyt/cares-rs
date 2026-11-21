//! Hash tables backed by the registered c-ares allocation callbacks.
use super::CaresAllocator;
use std::ops::{Deref, DerefMut};

// SAFETY: delegate to the same allocator implementation used by our vectors
// and boxes. Both interfaces have identical allocation/layout contracts.
unsafe impl allocator_api2::alloc::Allocator for CaresAllocator {
    fn allocate(&self, layout: std::alloc::Layout) -> Result<std::ptr::NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        std::alloc::Allocator::allocate(self, layout).map_err(|_| allocator_api2::alloc::AllocError)
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, layout: std::alloc::Layout) {
        unsafe { std::alloc::Allocator::deallocate(self, ptr, layout) }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HashMap<K, V>(hashbrown::HashMap<K, V, std::hash::RandomState, CaresAllocator>);

impl<K, V> HashMap<K, V> {
    pub(crate) fn new() -> Self {
        Self(hashbrown::HashMap::with_hasher_in(std::hash::RandomState::new(), CaresAllocator))
    }
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(hashbrown::HashMap::with_capacity_and_hasher_in(capacity, std::hash::RandomState::new(), CaresAllocator))
    }
}
impl<K: Eq + std::hash::Hash, V: PartialEq> PartialEq for HashMap<K, V> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}
impl<K: Eq + std::hash::Hash, V: Eq> Eq for HashMap<K, V> {}
impl<K, V> Default for HashMap<K, V> { fn default() -> Self { Self::new() } }
impl<K, V> Deref for HashMap<K, V> {
    type Target = hashbrown::HashMap<K, V, std::hash::RandomState, CaresAllocator>;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl<K, V> DerefMut for HashMap<K, V> { fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 } }
impl<K, V> IntoIterator for HashMap<K, V> {
    type Item = (K, V);
    type IntoIter = hashbrown::hash_map::IntoIter<K, V, CaresAllocator>;
    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}
impl<'a, K, V> IntoIterator for &'a HashMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = hashbrown::hash_map::Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

#[derive(Clone, Debug)]
pub(crate) struct HashSet<K>(hashbrown::HashSet<K, std::hash::RandomState, CaresAllocator>);

impl<K> HashSet<K> {
    pub(crate) fn new() -> Self {
        Self(hashbrown::HashSet::with_hasher_in(std::hash::RandomState::new(), CaresAllocator))
    }
}
impl<K> Default for HashSet<K> { fn default() -> Self { Self::new() } }
impl<K> Deref for HashSet<K> {
    type Target = hashbrown::HashSet<K, std::hash::RandomState, CaresAllocator>;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl<K> DerefMut for HashSet<K> { fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 } }
