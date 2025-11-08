pub trait CLinkedList {
    fn next(&mut self) -> &mut *mut Self;
}

pub fn chain_nodes<T>(mut elts: Vec<T>) -> T where T: CLinkedList {
    let mut tail = elts.pop().unwrap();
    while let Some(mut x) = elts.pop() /* O(1) */ {
        *(x.next()) = Box::into_raw(Box::new(tail));
        tail = x
    }
    tail
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

    #[test]
    fn test_chain_leaves() {
        let vec = vec![DummyNode::new(1), DummyNode::new(2), DummyNode::new(3)];
        unsafe {
            let head = chain_nodes(vec);
            assert_eq!(head.num, 1);
            let head = &*(head.next);
            assert_eq!(head.num, 2);
            let head = &*(head.next);
            assert_eq!(head.num, 3);
            assert_eq!(head.next, std::ptr::null_mut());
        }
    }
}
