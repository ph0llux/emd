#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel_buf, 
    macros::{map, uprobe}, 
    maps::{PerCpuArray, Queue}, 
    programs::ProbeContext,
};

use emd_common::{
    BUFFER_SIZE, QUEUE_SIZE, MAX_QUEUE_SIZE,
    calc_queue_elements,
};

#[cfg(feature = "log")]
use aya_log_ebpf::{debug, error};

#[map] // 
static BUFFER_QUEUE: Queue<[u8; BUFFER_SIZE]> = Queue::<[u8; BUFFER_SIZE]>::with_max_entries(QUEUE_SIZE, 0);

#[map] // 
static BUFFER: PerCpuArray<[u8; BUFFER_SIZE]> = PerCpuArray::<[u8; BUFFER_SIZE]>::with_max_entries(1, 0);

#[uprobe]
fn read_kernel_memory(ctx: ProbeContext) -> u32 {
    #[cfg(feature = "log")]
    debug!(&ctx, "Starting uprobe to read kernel memory.");

    let mut src_address: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => {
            #[cfg(feature = "log")]
            error!(&ctx, "Cannot read source address from probe-context.");
            return 1
        },
    };

    let dump_size: usize = match ctx.arg(1) {
        Some(value) => value,
        None => {
            #[cfg(feature = "log")]
            error!(&ctx, "Cannot read dumpsize from probe-context.");
            return 2
        },
    };
    if dump_size > MAX_QUEUE_SIZE {
        #[cfg(feature = "log")]
        error!(&ctx, "Given dump size ({}) is greater than maximum allowed dump size ({})", dump_size, MAX_QUEUE_SIZE);
        return 3;
    }

    let queue_elements = calc_queue_elements(dump_size);
    #[cfg(feature = "log")]
    debug!(&ctx, "Using {} queue elements");
    

    let buffer = unsafe {
        let ptr = match BUFFER.get_ptr_mut(0) {
            Some(ptr) => ptr,
            None => {
                #[cfg(feature = "log")]
                error!(&ctx, "Cannot assign buffer ptr. This is an application bug.");
                return 0;
            }
        };
        &mut *ptr
    };

    for i in 0..queue_elements {
        let queue_element_size = if i == queue_elements -1 && dump_size % BUFFER_SIZE != 0 {
            dump_size % BUFFER_SIZE
        } else {
            BUFFER_SIZE
        };
        unsafe {
            let src_ptr = src_address as *const u8;
            match bpf_probe_read_kernel_buf(src_ptr, &mut buffer[..queue_element_size]) {
                Err(_) => {
                    return 4
                },
                Ok(_) => {
                    if BUFFER_QUEUE.push(&(*buffer), 0).is_err() {
                        return 5;
                    }
                    src_address += queue_element_size as u64;
                }
            };
        }
    }
    0
}

// future implementation, if https://github.com/aya-rs/aya/issues/221 is implemented
/*fn read_page_offset_base(_ctx: ProbeContext) -> u32 {
    unsafe {
        let address = 0;
        bpf_kallsyms_lookup_name(PAGE_OFFSET_BASE.as_ptr() as *const i8, PAGE_OFFSET_BASE.len() as i32, 0, address as *mut u64);
        let mut buffer = [0u8; 256];
        match bpf_probe_read_kernel_buf(address as *const u8, &mut buffer[..8]) {
            Err(_) => {
                return 1
            },
            Ok(_) => {
                if BUFFER.push(&buffer, 0).is_err() {
                    return 2;
                }
            }
        };
        0
    }
}*/

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}