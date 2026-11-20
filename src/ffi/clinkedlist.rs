pub trait CLinkedList {
    fn next(&mut self) -> &mut *mut Self;
}

use super::ares_data::{AresData, DataType};

/// Construct the final C graph directly. Its partial prefix remains owned until
/// `into_raw`, so every failure drops both the prefix and the unlinked value.
pub(crate) struct ReplyList<T: CLinkedList + DataType> {
    head: *mut AresData<T>,
    tail: *mut T,
}
impl<T: CLinkedList + DataType> ReplyList<T> {
    pub(crate) fn new() -> Self { Self { head: std::ptr::null_mut(), tail: std::ptr::null_mut() } }
    pub(crate) fn is_empty(&self) -> bool { self.head.is_null() }
    pub(crate) fn push(&mut self, data: T) -> Result<(), i32> {
        if self.head.is_null() {
            self.head = crate::mem::into_raw(crate::mem::boxed(AresData { data_type: T::datatype(), data })?);
            self.tail = unsafe { &mut (*self.head).data };
        } else {
            let node = crate::mem::into_raw(crate::mem::boxed(data)?);
            unsafe { *(*self.tail).next() = node };
            self.tail = node;
        }
        Ok(())
    }
    pub(crate) fn into_raw(mut self) -> *mut T {
        let head = std::mem::replace(&mut self.head, std::ptr::null_mut());
        if head.is_null() { std::ptr::null_mut() } else { unsafe { &mut (*head).data } }
    }
}
impl<T: CLinkedList + DataType> Drop for ReplyList<T> {
    fn drop(&mut self) {
        if !self.head.is_null() { unsafe { super::ares_data::free_chain::<T>(self.head.cast()) }; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyNode {
        next: *mut DummyNode,
        num: u8,
    }

    impl DummyNode {
        fn new(num: u8) -> DummyNode {
            DummyNode { next: std::ptr::null_mut(), num }
        }
    }

    impl CLinkedList for DummyNode {
        fn next(&mut self) -> &mut *mut Self { &mut self.next }
    }
    impl DataType for DummyNode {
        fn datatype() -> super::super::ares_data::AresDataType { super::super::ares_data::AresDataType::MxReply }
    }

    #[test]
    fn test_chain_leaves() {
        let mut list = ReplyList::new();
        for n in [1, 2, 3] { list.push(DummyNode::new(n)).unwrap(); }
        unsafe {
            let head = &(*list.head).data;
            assert_eq!(head.num, 1);
            let n2 = head.next;
            assert_eq!((*n2).num, 2);
            let n3 = (*n2).next;
            assert_eq!((*n3).num, 3);
            assert_eq!((*n3).next, std::ptr::null_mut());
            // The builder owns the whole prefix until the explicit transfer.
        }
    }
}
