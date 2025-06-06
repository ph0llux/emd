// - parent
use super::*;

pub(crate) fn get_page_offset_base(buffer_queue: &mut Queue<&mut MapData, [u8; BUFFER_SIZE]>) -> anyhow::Result<u64>{
    let page_offset_base_addr = get_page_offset_base_address_from_file()?;
    read_kernel_memory(page_offset_base_addr, 8);
    let slice: &[u8] = &buffer_queue.pop(0)?[..8];
    Ok(u64::from_le_bytes(slice.try_into()?))
}

pub(crate) fn get_base_addr() -> Result<usize, anyhow::Error> {
    let me = Process::myself()?;
    let maps = me.maps()?;

    for entry in maps {
        if entry.perms.contains(MMPermissions::EXECUTE) && 
        entry.perms.contains(MMPermissions::READ) && 
        entry.perms.contains(MMPermissions::PRIVATE) {
            return Ok((entry.address.0 - entry.offset) as usize);
        }
    }
    anyhow::bail!("Failed to find executable region")
}

pub(crate) fn memory_size() -> anyhow::Result<u64> {
    let memory_ranges = extract_mem_range(SEPARATOR_SYSTEM_RAM)?;
    let mut total_size = 0;
    for range in memory_ranges {
        total_size += range.end - range.start;
    }
    Ok(total_size)
}