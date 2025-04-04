#![cfg_attr(not(feature = "std"), no_std)]

// - STD
#[cfg(feature = "std")]
use std::{
    ops::Range,
    path::Path,
    fs::{File, read_to_string},
    io::{Result, BufReader, BufRead, Error, ErrorKind},
};

// This file exists to enable the library target.
pub const BUFFER_SIZE: usize = 256; // 512 bytes is the maximum allowed stack size of an ebpf program. We won't reach this.
pub const QUEUE_SIZE: u32 = 64;
pub const MAX_QUEUE_SIZE: usize = QUEUE_SIZE as usize * BUFFER_SIZE;

// IOMEM
pub const PROC_IOMEM: &str = "/proc/iomem";
pub const SEPARATOR_SYSTEM_RAM: &str = " : System RAM";
pub const SEPARATOR_HYPHEN: char = '-';

// KALLSYMS
pub const PROC_KALLSYMS: &str = "/proc/kallsyms";
pub const PAGE_OFFSET_BASE: &str = "page_offset_base";
const PROC_KPTR_RESTRICT: &str = "/proc/sys/kernel/kptr_restrict";
const PROC_OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const SYSTEMMAP_PREFIX: &str = "/boot/System.map-";

// self exe
pub const PROC_SELF_EXE: &str = "/proc/self/exe";

// eBPF fns
pub const READ_KERNEL_MEM: &str = "read_kernel_memory";

// - Errors
pub const ERROR_DUMP_MEMORY_IOMEM_SEPARATE_KEY_VAL_MAP: &str = "There is no left side in key/value pair";
pub const ERROR_DUMP_MEMORY_IOMEM_CAPSYSADM: &str = "Need CAP_SYS_ADMIN to read /proc/iomem";
pub const ERROR_PATH_READ_SYS: &str = "An error occured while trying to read necessary data from /sys";

#[derive(Debug)]
pub struct LimeHeader {
    pub magic_bytes: u32,
    pub header_version: u32,
    pub start_address: u64,
    pub end_address: u64,
    pub reserved_space: [u8; 8],
}

impl Default for LimeHeader {
    fn default() -> Self {
        Self {
            magic_bytes: 0x4C694D45,
            header_version: 1,
            start_address: 0,
            end_address: 0,
            reserved_space: [0u8; 8],
        }
    }
}

impl LimeHeader {
    pub fn new(start_address: u64, end_address: u64) -> Self {
        Self {
            start_address,
            end_address,
            ..Default::default()
        }
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&self.magic_bytes.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.header_version.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.start_address.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.end_address.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.reserved_space);
        bytes
    }
}

pub enum Header {
    None,
    Lime(LimeHeader),
}

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
pub fn get_page_offset_base_address_from_file() -> Result<u64>{
    let file = match get_kptr_restrict()? {
        KptrRestrict::Full => get_system_map_fd()?,
        _ => get_kallsyms_fd()?,
    };
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

fn get_system_map_fd() -> Result<File> {
    let os_release = read_to_string(PROC_OSRELEASE)?;
    let path = Path::new(SYSTEMMAP_PREFIX).join(os_release);
    File::open(path)
}

fn get_kallsyms_fd() -> Result<File> {
    let path = Path::new(PROC_KALLSYMS);
    File::open(path)
}

#[cfg(feature = "std")]
fn get_kptr_restrict() -> Result<KptrRestrict> {
    let value_str = read_to_string(PROC_KPTR_RESTRICT)?;
    let value = value_str.trim().parse::<u8>().unwrap();
    KptrRestrict::try_from(value)
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

#[cfg(feature = "std")]
enum KptrRestrict {
    None,
    Partial,
    Full
}

#[cfg(feature = "std")]
impl TryFrom<u8> for KptrRestrict {
    type Error = std::io::Error;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(KptrRestrict::None),
            1 => Ok(KptrRestrict::Partial),
            2 => Ok(KptrRestrict::Full),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{value}"))),
        }
    }
}