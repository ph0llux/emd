// - STD
use std::{
    fs::File, 
    io::{BufWriter, Write},
     ops::Range, path::PathBuf
};

// - modules
mod address_calculation;
mod memory_dump;

// - re-exports
use address_calculation::*;
use memory_dump::*;

// - External
use procfs::process::{Process, MMPermissions};
use aya::{programs::UProbe, Ebpf};
use aya::maps::{MapData, Queue};
use emd_common::*;

use zstd::stream::Encoder as ZstdEncoder;
use lz4_flex::frame::FrameEncoder as Lz4Encoder;

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
    #[clap(short='l', long="loglevel", global=true, required=false, value_enum, default_value="info")]
    log_level: LogLevel,

    /// sets the compression.
    #[clap(short='c', long="compress", global=true, required=false, value_enum, default_value="none")]
    compression: Compression,

    /// sets the output-format.
    #[clap(short='f', long="output-format", global=true, value_enum, default_value="raw")]
    output_format: OutputFormat
}

#[derive(ValueEnum, Clone)]
enum Compression {
    None,
    Zstd,
    Lz4,
}

#[derive(ValueEnum, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Raw,
    Lime,
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn _read_kernel_memory(_src_address: u64, _dump_size: usize) {}

#[no_mangle]
#[inline(never)]
fn read_kernel_memory(offset: u64, dump_size: usize) {
    let func: extern "C" fn(u64, usize) = _read_kernel_memory;
    // unsafe block is necessary to ensure the compiler will not optimize this away.
    unsafe {
        std::ptr::read_volatile(&func);
        func(offset, dump_size);
    }
}

fn main() -> anyhow::Result<()> {

    //TODO: Check if you are root || check if you've got appropriate capabilities.

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

    let pid = std::process::id();
    info!("Using PID: {pid}");

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
    let mut ebpf = Ebpf::load(emd_ebpf::EBPF_BINARY)?;

    info!("Initialize function.");
    let program: &mut UProbe = ebpf.program_mut(READ_KERNEL_MEM).unwrap().try_into()?;
    program.load()?;

    let fn_addr = read_kernel_memory as *const () as usize;
    let offset = (fn_addr - get_base_addr()?) as u64;

    info!("Attaching program.");
    program.attach(None, offset, PROC_SELF_EXE, None)?;

    // get page_offset_base
    info!("Initializing buffer queue.");
    let mut buffer_queue = Queue::try_from(ebpf.map_mut("BUFFER_QUEUE").unwrap())?;
    dump_physical_memory(&args, &mut buffer_queue)
}