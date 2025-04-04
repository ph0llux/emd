// - parent
use super::*;

pub fn dump_physical_memory(
    args: &Cli, 
    buffer_queue: &mut Queue<&mut MapData, [u8; BUFFER_SIZE]>
) -> anyhow::Result<()> {
    info!("Extracting memory ranges.");
    let system_ram_ranges = extract_mem_range(SEPARATOR_SYSTEM_RAM)?;
    info!("Calculating page offset base.");
    let page_offset_base = get_page_offset_base(buffer_queue)?;
    dump_mem(args, buffer_queue, system_ram_ranges, page_offset_base)
}

fn prepare_writer(args: &Cli) -> anyhow::Result<Box<dyn Write>> {
    let file = File::create(&args.output)?;
    match &args.compression {
        Compression::None => {
            Ok(Box::new(file))
        },
        Compression::Zstd => {
            let encoder = ZstdEncoder::new(file, 3)?;
            Ok(Box::new(encoder.auto_finish()))
        },
        Compression::Lz4 => Ok(Box::new(Lz4Encoder::new(file)))
    }
}

fn dump_mem(
    args: &Cli,
    buffer_queue: &mut Queue<&mut MapData, [u8; BUFFER_SIZE]>,
    memory_range: Vec<Range<u64>>,
    mapping_offset: u64) -> anyhow::Result<()> {

    let mut output_file = BufWriter::new(prepare_writer(args)?);

    let mut header = match args.output_format {
        OutputFormat::Lime => Header::Lime(LimeHeader::default()),
        OutputFormat::Raw => Header::None,
    };

    for range in memory_range {
        let range_len = range.end - range.start;
        let range_end = range.end;
        let range_start = range.start;
        info!("Dumping 0x{range_start:x} - 0x{range_end:x}");
        for offset in range.step_by(MAX_QUEUE_SIZE) {

            debug!("Dumping 0x{offset:x}");
            let remaining = (range_len - (offset - range_start)) as usize;
            let dump_size = if remaining < MAX_QUEUE_SIZE {
                remaining
            } else {
                MAX_QUEUE_SIZE
            };
            
            read_kernel_memory(mapping_offset+offset, dump_size);

            let queue_elements = calc_queue_elements(dump_size);
            let mut unreadable_offsets = Vec::new();
            let mut optional_header_end_address = offset; // only used by e.g. LimeHeader
            for i in 0..queue_elements {
                let queue_element_size = if i == queue_elements && dump_size % BUFFER_SIZE != 0 {
                    dump_size % BUFFER_SIZE
                } else {
                    BUFFER_SIZE
                };
                let buffer = match buffer_queue.pop(0) {
                    Ok(value) => {
                        optional_header_end_address += queue_element_size as u64;
                        value
                    },
                    Err(_) => {
                        unreadable_offsets.push((offset, i));
                        [0u8; BUFFER_SIZE]
                    }
                };

                if let Header::Lime(header) = &mut header {
                    header.start_address = offset;
                    header.end_address = optional_header_end_address;
                    output_file.write_all(&header.as_bytes())?;
                }
                output_file.write_all(&buffer[..queue_element_size])?;
            }
            for (offset, i) in unreadable_offsets {
                // only necessary to print in warning.
                let start_offset = offset + (BUFFER_SIZE * i) as u64;
                let end_offset = offset + (BUFFER_SIZE * (queue_elements-1)) as u64;
                warn!("Could not read 0x{start_offset:x} - 0x{end_offset:x}. Writing zeros for appropriate zone.");
            }
        }
    }
    output_file.flush()?; // flush the buffer

    Ok(())
}