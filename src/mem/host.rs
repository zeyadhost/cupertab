/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Cross-platform memory management wrappers using the host's system calls.

#[cfg(target_os = "emscripten")]
pub(super) fn allocate_window(size: usize) -> std::io::Result<*mut core::ffi::c_void> {
    unsafe extern "C" {
        fn sbrk(increment: isize) -> *mut core::ffi::c_void;
    }

    // wasm32 Emscripten's program break only grows. Reserve fresh zeroed
    // bytes without mmap's eager clear; dropped windows stay in our pool.
    let page_mask = super::PAGE_SIZE as usize - 1;
    let reserve = (size + page_mask).try_into().unwrap();
    let ptr = unsafe { sbrk(reserve) };
    if ptr == core::ptr::without_provenance_mut(usize::MAX) {
        // malloc may still be able to reuse a hole below the break.
        return unsafe { allocate_memory(size) };
    }
    Ok(ptr.wrapping_byte_add(ptr.addr().wrapping_neg() & page_mask))
}

#[cfg(all(target_os = "emscripten", test))]
mod tests {
    #[test]
    fn fresh_windows_are_aligned_zero_and_disjoint_from_the_heap() {
        let size = 3 * crate::mem::PAGE_SIZE as usize;
        let window = || {
            let ptr = super::allocate_window(size).unwrap().cast::<u8>();
            assert_eq!(ptr.addr() % crate::mem::PAGE_SIZE as usize, 0);
            ptr
        };
        let first_ptr = window();
        let first = unsafe { std::slice::from_raw_parts_mut(first_ptr, size) };
        assert!(first.iter().all(|&byte| byte == 0));
        first.fill(1);
        let heap = vec![2u8; 8 * 1024 * 1024];
        let second_ptr = window();
        let ranges = [
            first_ptr.addr()..first_ptr.addr() + size,
            heap.as_ptr().addr()..heap.as_ptr().addr() + heap.len(),
            second_ptr.addr()..second_ptr.addr() + size,
        ];
        for (i, a) in ranges.iter().enumerate() {
            assert!(ranges[..i]
                .iter()
                .all(|b| a.end <= b.start || b.end <= a.start));
        }
        let second = unsafe { std::slice::from_raw_parts_mut(second_ptr, size) };
        assert!(second.iter().all(|&byte| byte == 0));
        second.fill(3);
        assert!(first.iter().all(|&byte| byte == 1));
        assert!(heap.iter().all(|&byte| byte == 2));
    }
}

/// Cross-platform memory allocation using the host's system calls.
/// Returns an address aligned to the guest's 4KB page boundaries.
///
/// - The function returns a raw pointer to allocated memory.
///   The caller is responsible for managing that memory.
/// - The returned pointer must be freed using the corresponding
///   [`free_memory`] call.
#[cfg(windows)]
pub(super) unsafe fn allocate_memory(size: usize) -> std::io::Result<*mut core::ffi::c_void> {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    };

    let ptr = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if ptr.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ptr)
}

#[cfg(unix)]
pub(super) unsafe fn allocate_memory(size: usize) -> std::io::Result<*mut core::ffi::c_void> {
    use libc::{mmap, sysconf, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};

    const PAGE_SIZE: usize = crate::mem::PAGE_SIZE as usize;
    let host_page_size = unsafe { sysconf(libc::_SC_PAGESIZE) as usize };

    assert!(
        host_page_size >= PAGE_SIZE,
        "Hosts with smaller than 4KiB pages are not supported."
    );

    let ptr = unsafe {
        mmap(
            std::ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ptr)
}

/// Cross-platform memory free using the host's system calls.
///
/// # Safety
/// - The address and size should match parameters and result of the
///   [`allocate_memory`] call.
#[cfg(windows)]
pub(super) unsafe fn free_memory(
    address: *mut core::ffi::c_void,
    _size: usize,
) -> std::io::Result<()> {
    use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};

    let res = unsafe { VirtualFree(address, 0, MEM_RELEASE) };

    if res == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
pub(super) unsafe fn free_memory(
    address: *mut core::ffi::c_void,
    size: usize,
) -> std::io::Result<()> {
    use libc::munmap;

    let res = unsafe { munmap(address, size) };

    if res == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
