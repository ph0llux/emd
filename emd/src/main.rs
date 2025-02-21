// - STD
use std::{
    fs::File, 
    io::{self, BufRead, BufWriter, Write},
     ops::Range, path::{Path, PathBuf}
};


// - modules
mod iomem;

// - re-exports
use iomem::*;

// - External
use procfs::process::Process;
use aya::{programs::UProbe, Ebpf};
use aya::maps::{MapData, Queue};
use emd_common::*;

use clap::{
    Parser,
    ValueEnum,
};
use log::{LevelFilter, info, debug, warn};

#[derive(Parser)]
#[clap(about, version, author)]
struct Cli {
    /// sets the target file (where your memory will be dumped to).
    #[clap(short='o', long="outputfile", required=true)]
    output: PathBuf,

    /// sets the log level - default is info.
    #[clap(short='l', long="loglevel", required=false, value_enum, default_value="info")]
    log_level: LogLevel,
}

#[derive(ValueEnum, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn read_kernel_memory(_src_address: u64, _dump_size: usize) {}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let log_level = match args.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    info!("Initializing ebpf memory dumper.");

    info!("Setting rlimits.");
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {}", ret);
    }

    info!("Load eBPF program.");
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/emd"
    )))?;

    info!("Initialize function.");
    let program: &mut UProbe = ebpf.program_mut(READ_KERNEL_MEM).unwrap().try_into()?;
    program.load()?;

    let fn_addr = read_kernel_memory as *const () as usize;
    let offset = (fn_addr - get_base_addr()?) as u64;

    info!("Attaching program.");
    program.attach(None, offset, PROC_SELF_EXE, None)?;

    // get page_offset_base
    info!("Initializing buffer queue.");
    let mut buffer_queue = Queue::try_from(ebpf.map_mut("BUFFER").unwrap())?;
    info!("Calculating page offset base");
    let page_offset_base = get_page_offset_base(&mut buffer_queue)?;

    info!("Extract memory ranges.");
    let system_ram_ranges = extract_system_ram_ranges()?;
    let mut output_file = BufWriter::new(File::create(&args.output)?);
    
    for range in system_ram_ranges {
        let range_len = range.end - range.start;
        let range_end = range.end;
        let range_start = range.start;
        info!("Dumping 0x{range_start:x} - 0x{range_end:x}");
        for offset in range.step_by(BUFFER_SIZE) {
            debug!("Dumping 0x{offset:x}");
            let remaining = (range_len - (offset - range_start)) as usize;
            if remaining < BUFFER_SIZE {
                unsafe {
                    // unsafe block is necessary to ensure the compiler will not optimize this away.
                    let func: extern "C" fn(u64, usize) = read_kernel_memory;
                    std::ptr::read_volatile(&func);
                    func(page_offset_base+offset, remaining);
                }
            } else {
                unsafe {
                    // unsafe block is necessary to ensure the compiler will not optimize this away.
                    let func: extern "C" fn(u64, usize) = read_kernel_memory;
                    std::ptr::read_volatile(&func);
                    func(page_offset_base+offset, BUFFER_SIZE);
                }
            }
            output_file.write_all(&buffer_queue.pop(0)?)?;
        }
    }
    output_file.flush()?;
    
    Ok(())
}

fn get_page_offset_base(buffer_queue: &mut Queue<&mut MapData, [u8; BUFFER_SIZE]>) -> anyhow::Result<u64>{
    let path = Path::new(PROC_KALLSYMS);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut kallsyms_symb_addr = 0;
    for line in reader.lines() {
        let line = line?;
        if line.contains(PAGE_OFFSET_BASE) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(offset_str) = parts.first() {
                kallsyms_symb_addr = u64::from_str_radix(offset_str, 16)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                break;
            }
        }
    }

    // Read the content of the kernel variable page_offset_base to get the offset of direct mapping region
    
    unsafe {
        // unsafe block is necessary to ensure the compiler will not optimize this away.
        let func: extern "C" fn(u64, usize) = read_kernel_memory;
        std::ptr::read_volatile(&func);
        func(kallsyms_symb_addr, 8);
    }
    let slice: &[u8] = &buffer_queue.pop(0)?[..8];
    Ok(u64::from_le_bytes(slice.try_into()?))
}

fn get_base_addr() -> Result<usize, anyhow::Error> {
    let me = Process::myself()?;
    let maps = me.maps()?;

    for entry in maps {
        if entry.perms.contains("r-xp") { //TODO: better implementation using procfs version 0.17?!
            return Ok((entry.address.0 - entry.offset) as usize);
        }
    }

    anyhow::bail!("Failed to find executable region")
}