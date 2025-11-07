/// Keep MSRV below 1.77
/// This is a subject to be removed in the future

#[macro_export]
macro_rules! offset_of {
    ($parent:ty, $field:tt) => {{
        let base: *const $parent = core::ptr::NonNull::<$parent>::dangling().as_ptr();
        let field = unsafe { core::ptr::addr_of!((*base).$field) };
        (field as usize) - (base as usize)
    }};
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use crate::offset_of;

    const fn align_up(off: usize, align: usize) -> usize {
        // align is a power of two for Rust types, so this is fine.
        (off + align - 1) & !(align - 1)
    }

    #[repr(C)]
    struct S1 {
        a: u8,
        b: u32,
        c: u16,
    }

    #[test]
    fn offsets_s1() {
        // Expected offsets per C layout rules.
        let a_off = 0usize;

        let b_align = align_of::<u32>();
        let b_off = align_up(a_off + size_of::<u8>(), b_align);

        let c_align = align_of::<u16>();
        let c_off = align_up(b_off + size_of::<u32>(), c_align);

        assert_eq!(offset_of!(S1, a), a_off);
        assert_eq!(offset_of!(S1, b), b_off);
        assert_eq!(offset_of!(S1, c), c_off);
    }

    #[test]
    fn size_and_alignment_match_c_rules() {
        // For S2 as an example
        let a_off = 0usize;
        let b_off = align_up(a_off + size_of::<u8>(), align_of::<u32>());
        let c_off = align_up(b_off + size_of::<u32>(), align_of::<u16>());
        let end   = c_off + size_of::<u16>();
        let size  = align_up(end, align_of::<S1>());

        assert_eq!(size_of::<S1>(), size);
    }
}
