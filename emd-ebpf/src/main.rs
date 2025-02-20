#![no_std]
#![no_main]


use aya_ebpf::{
    helpers::bpf_probe_read_kernel_buf, 
    macros::{map, uprobe}, 
    maps::Queue, 
    programs::ProbeContext,
};

use emd_common::{
    BUFFER_SIZE, QUEUE_SIZE
};

//use aya_log_ebpf::info;

#[map] // 
static BUFFER: Queue<[u8; BUFFER_SIZE]> = Queue::<[u8; BUFFER_SIZE]>::with_max_entries(QUEUE_SIZE, 0);

#[uprobe]
fn read_kernel_memory(ctx: ProbeContext) -> u32 {
    let src_address: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => return 1,
    };

    let dump_size: usize = match ctx.arg(1) {
        Some(value) => value,
        None => return 2,
    };
    if dump_size > BUFFER_SIZE {
        return 3;
    }
    
    let mut buffer = [0u8; BUFFER_SIZE];
    unsafe {
        match bpf_probe_read_kernel_buf(src_address as *const u8, &mut buffer[..dump_size]) {
            Err(_) => {
                return 4
            },
            Ok(_) => {
                if BUFFER.push(&buffer, 0).is_err() {
                    return 5;
                }
            }
        };
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}