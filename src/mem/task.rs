//! Pinned, type-erased task storage with one fallible allocation. Keeping the
//! small unsafe ownership boundary here leaves the async runtime safe Rust.
use std::future::Future;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::pin::Pin;
use std::ptr::NonNull;
use std::task::{Context, Poll};

pub(crate) struct Task<E> {
    ptr: NonNull<()>,
    poll: unsafe fn(NonNull<()>, &mut Context<'_>) -> bool,
    finish: unsafe fn(NonNull<()>, Result<(), E>),
    destroy: unsafe fn(NonNull<()>),
}

struct Data<F: Future, C> { future: F, output: Option<F::Output>, callback: Option<C> }

impl<E> Task<E> {
    pub(crate) fn new<F, C>(future: F, callback: C) -> Result<Self, C>
    where F: Future + 'static, C: FnOnce(Result<F::Output, E>) + 'static {
        let Ok(storage) = super::boxed(MaybeUninit::uninit()) else { return Err(callback); };
        let data = super::initialize(storage, Data { future, output: None, callback: Some(callback) });
        let ptr = NonNull::from(Box::leak(data)).cast();
        Ok(Self { ptr, poll: poll::<F, C>, finish: finish::<F, C, E>, destroy: destroy::<F, C> })
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        // The pointee is never moved and the unique Task owns its poll access.
        unsafe { (self.poll)(self.ptr, cx) }
    }
    pub(crate) fn finish(self, result: Result<(), E>) {
        let this = ManuallyDrop::new(self);
        // Consumes the allocation, so Task::drop must not run afterward.
        unsafe { (this.finish)(this.ptr, result) };
    }
}
impl<E> Drop for Task<E> {
    fn drop(&mut self) { unsafe { (self.destroy)(self.ptr) }; }
}

unsafe fn poll<F: Future, C>(ptr: NonNull<()>, cx: &mut Context<'_>) -> bool {
    let data = unsafe { &mut *ptr.cast::<Data<F, C>>().as_ptr() };
    // Only future is structurally pinned; output and callback are never exposed
    // as pinned fields. finish/destroy both drop the future in its original box.
    match unsafe { Pin::new_unchecked(&mut data.future) }.poll(cx) {
        Poll::Ready(output) => { data.output = Some(output); true }
        Poll::Pending => false,
    }
}

unsafe fn finish<F: Future, C: FnOnce(Result<F::Output, E>), E>(ptr: NonNull<()>, result: Result<(), E>) {
    let data = unsafe { &mut *ptr.cast::<Data<F, C>>().as_ptr() };
    let callback = data.callback.take();
    let output = match result { Err(e) => Some(Err(e)), Ok(()) => data.output.take().map(Ok) };
    unsafe { destroy::<F, C>(ptr) };
    // Drop the future and release storage before a potentially reentrant callback.
    if let (Some(callback), Some(output)) = (callback, output) { callback(output); }
}

unsafe fn destroy<F: Future, C>(ptr: NonNull<()>) {
    unsafe { super::drop_box(ptr.cast::<Data<F, C>>().as_ptr()) };
}
