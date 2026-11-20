//! The allocator-aware equivalent of Arc<AtomicBool> for the executor's waker.
//! RawWaker is necessary because std::task::Wake requires a global-allocator Arc.
use std::sync::atomic::{fence, AtomicBool, AtomicUsize, Ordering};
use std::task::{RawWaker, RawWakerVTable, Waker};

pub(crate) struct ReadyFlag(Waker);
struct State { refs: AtomicUsize, ready: AtomicBool }

impl ReadyFlag {
    pub(crate) fn new() -> Result<Self, super::NoMemory> {
        let ptr = super::into_raw(super::boxed(State { refs: AtomicUsize::new(1), ready: AtomicBool::new(true) })?);
        // A RawWaker owns one reference; its vtable maintains thread-safe counts.
        Ok(Self(unsafe { Waker::from_raw(RawWaker::new(ptr.cast(), &VTABLE)) }))
    }
    fn state(&self) -> &State {
        // The private Waker is constructed only above and owns a live reference.
        unsafe { &*self.0.data().cast::<State>() }
    }
    pub(crate) fn waker(&self) -> &Waker { &self.0 }
    pub(crate) fn take(&self) -> bool { self.state().ready.swap(false, Ordering::AcqRel) }
    pub(crate) fn clear(&self) { self.state().ready.store(false, Ordering::Release); }
    pub(crate) fn is_set(&self) -> bool { self.state().ready.load(Ordering::Acquire) }
}

const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_ref, release);
unsafe fn clone(ptr: *const ()) -> RawWaker {
    let state = unsafe { &*ptr.cast::<State>() };
    // Match Arc's overflow defense; reference-count overflow is not OOM.
    if state.refs.fetch_add(1, Ordering::Relaxed) >= isize::MAX as usize { std::process::abort(); }
    RawWaker::new(ptr, &VTABLE)
}
unsafe fn wake_ref(ptr: *const ()) {
    unsafe { &*ptr.cast::<State>() }.ready.store(true, Ordering::Release);
}
unsafe fn wake(ptr: *const ()) {
    unsafe { wake_ref(ptr); release(ptr); }
}
unsafe fn release(ptr: *const ()) {
    if unsafe { &*ptr.cast::<State>() }.refs.fetch_sub(1, Ordering::Release) == 1 {
        fence(Ordering::Acquire);
        unsafe { super::drop_box(ptr.cast::<State>().cast_mut()) };
    }
}
