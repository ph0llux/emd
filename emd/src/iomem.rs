// - parent
use super::*;

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
///This method results you the 'System RAM' entries as a Vec<std::ops::Range<u64>>.
pub fn extract_system_ram_ranges() -> anyhow::Result<Vec<Range<u64>>> {
    let path = Path::new(PROC_IOMEM);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut ranges = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.contains(SEPARATOR_SYSTEM_RAM) {
            if let Some((start, end)) = parse_memory_range(&line) {
                ranges.push(start..(end + 1));
            }
        }
    }

    Ok(ranges)
}

pub fn parse_memory_range(line: &str) -> Option<(u64, u64)> {
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