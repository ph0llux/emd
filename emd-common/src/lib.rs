#![no_std]

// This file exists to enable the library target.
pub const BUFFER_SIZE: usize = 256; // 512 bytes is the stack size of an ebpf program. We won't reach this.
pub const QUEUE_SIZE: u32 = 64;
pub const MAX_QUEUE_SIZE: usize = QUEUE_SIZE as usize * BUFFER_SIZE;

// IOMEM
pub const PROC_IOMEM: &str = "/proc/iomem";
pub const SEPARATOR_SYSTEM_RAM: &str = " : System RAM";
pub const SEPARATOR_HYPHEN: char = '-';

// KALLSYMS
pub const PROC_KALLSYMS: &str = "/proc/kallsyms";
pub const PAGE_OFFSET_BASE: &str = "page_offset_base";

// self exe
pub const PROC_SELF_EXE: &str = "/proc/self/exe";

// eBPF fns
pub const READ_KERNEL_MEM: &str = "read_kernel_memory";

// - Errors
pub const ERROR_DUMP_MEMORY_IOMEM_SEPARATE_KEY_VAL_MAP: &str = "There is no left side in key/value pair";
pub const ERROR_DUMP_MEMORY_IOMEM_CAPSYSADM: &str = "Need CAP_SYS_ADMIN to read /proc/iomem";

pub fn calc_queue_elements(dump_size: usize) -> usize {
    if dump_size % BUFFER_SIZE == 0 {
            dump_size / BUFFER_SIZE
    } else {
        dump_size / BUFFER_SIZE + 1
    }
}