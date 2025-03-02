#![cfg_attr(not(feature = "std"), no_std)]

// - STD
#[cfg(feature = "std")]
use std::{
    ops::Range,
    path::Path,
    fs::File,
    io::{Result, BufReader, BufRead, Error, ErrorKind},
};

// This file exists to enable the library target.
pub const BUFFER_SIZE: usize = 256; // 512 bytes is the stack size of an ebpf program. We won't reach this.
pub const QUEUE_SIZE: u32 = 64;
pub const MAX_QUEUE_SIZE: usize = QUEUE_SIZE as usize * BUFFER_SIZE;

// IOMEM
pub const PROC_IOMEM: &str = "/proc/iomem";
pub const SEPARATOR_SYSTEM_RAM: &str = " : System RAM";
pub const SEPARATOR_HYPHEN: char = '-';

// SYS
pub const SYS_DEVICES: &str = "/sys/bus/pci/devices";
pub const SYS_UEVENT: &str = "uevent";
pub const SYS_UEVENT_IDENTIFIER_DRIVER: &str = "DRIVER=";
pub const DRIVER_NVIDIA: &str = "nvidia";

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
pub const ERROR_PATH_READ_SYS: &str = "An error occured while trying to read necessary data from /sys";

pub fn calc_queue_elements(dump_size: usize) -> usize {
    if dump_size % BUFFER_SIZE == 0 {
            dump_size / BUFFER_SIZE
    } else {
        dump_size / BUFFER_SIZE + 1
    }
}

/// This method results you the current map of the system's memory for each physical device. Normally, could be found at
/// /proc/iomem. 
/// # Example output
///As following you can see an  **partial** example output of the content of file **/proc/iomem**:
/// ```bash
/// 00000000-00000fff : Reserved
/// 00001000-0009efff : System RAM
/// 0009f000-000fffff : Reserved
///   000a0000-000bffff : PCI Bus 0000:00
///   000f0000-000fffff : System ROM
/// 00100000-5894bfff : System RAM
/// 5894c000-589c6fff : Reserved
/// 589c7000-5e068fff : System RAM
/// 5e069000-5e968fff : Reserved
/// 5e969000-6cb7efff : System RAM
/// 6cb7f000-6cf4efff : Unknown E820 type
/// 6cf4f000-6ed6efff : Reserved
/// 6ed6f000-6fbcefff : ACPI Non-volatile Storage
/// 6fbcf000-6fc4efff : ACPI Tables
/// 6fc4f000-6fc4ffff : System RAM
/// 6fc50000-7d7fffff : Reserved
///   70200000-75f7ffff : INT0E0C:00
///   79800000-7d7fffff : Graphics Stolen Memory
/// 7d800000-dfffffff : PCI Bus 0000:00
/// ```
///The first column displays the memory registers used by each of the different types of memory. The second column
///lists the kind of memory located within those registers and displays which memory registers are used by the kernel
///within the system RAM or, if the network interface card has multiple Ethernet ports, the memory registers assigned
///for each port.
///This method results you the entries as a Vec<std::ops::Range<u64>> for the given identifier (e.g. "System RAM").
#[cfg(feature = "std")]
pub fn extract_mem_range<I: Into<String>>(identifier: I) -> Result<Vec<Range<u64>>> {
    let identifier = identifier.into();
    let path = Path::new(PROC_IOMEM);
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut ranges = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.contains(&identifier) {
            if let Some((start, end)) = parse_memory_range(&line) {
                ranges.push(start..(end + 1));
            }
        }
    }

    Ok(ranges)
}

#[cfg(feature = "std")]
pub fn get_page_offset_base_address() -> Result<u64>{
    let path = Path::new(PROC_KALLSYMS);
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if line.contains(PAGE_OFFSET_BASE) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(offset_str) = parts.first() {
                return u64::from_str_radix(offset_str, 16)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))
            }
        }
    }
    // if no page offset base is found, KASLR is disabled...?
    Ok(0)
}

#[cfg(feature = "std")]
fn parse_memory_range(line: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if let Some(range_part) = parts.first() {
        let bounds: Vec<&str> = range_part.split(SEPARATOR_HYPHEN).collect();
        if bounds.len() == 2 {
            if let (Ok(start), Ok(end)) = (u64::from_str_radix(bounds[0], 16), u64::from_str_radix(bounds[1], 16)) {
                return Some((start, end));
            }
        }
    }
    None
}
