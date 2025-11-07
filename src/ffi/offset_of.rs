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

    #[repr(C)]
    struct S2 {
        x: u32,
        y: u64,
        z: u8,
    }

    #[test]
    fn offsets_s2() {
        let x_off = 0usize;

        let y_align = align_of::<u64>();
        let y_off = align_up(x_off + size_of::<u32>(), y_align);

        let z_align = align_of::<u8>();
        let z_off = align_up(y_off + size_of::<u64>(), z_align);

        assert_eq!(offset_of!(S2, x), x_off);
        assert_eq!(offset_of!(S2, y), y_off);
        assert_eq!(offset_of!(S2, z), z_off);
    }

    #[repr(C)]
    struct S3 {
        head: u8,
        buf: [u16; 3],   // array alignment = element alignment
        tail: u32,
    }

    #[test]
    fn offsets_s3() {
        let head_off = 0usize;

        let buf_align = align_of::<[u16; 3]>(); // same as align_of::<u16>()
        let buf_off = align_up(head_off + size_of::<u8>(), buf_align);

        let tail_align = align_of::<u32>();
        let tail_off = align_up(buf_off + size_of::<[u16; 3]>(), tail_align);

        assert_eq!(offset_of!(S3, head), head_off);
        assert_eq!(offset_of!(S3, buf), buf_off);
        assert_eq!(offset_of!(S3, tail), tail_off);
    }

    // Optional: sanity-check that the struct size matches C layout expectations too.
    #[test]
    fn size_and_alignment_match_c_rules() {
        // For S2 as an example
        let x_off = 0usize;
        let y_off = align_up(x_off + size_of::<u32>(), align_of::<u64>());
        let z_off = align_up(y_off + size_of::<u64>(), align_of::<u8>());
        let end   = z_off + size_of::<u8>();
        let size  = align_up(end, align_of::<S2>());

        assert_eq!(size_of::<S2>(), size);
    }
}
