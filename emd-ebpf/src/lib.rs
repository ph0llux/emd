// - external
use aya::include_bytes_aligned;

#[cfg(feature = "build")]
pub const EBPF_BINARY: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/emd_ebpf"));
#[cfg(not(feature = "build"))]
pub const EBPF_BINARY: &[u8] = include_bytes_aligned!("../assets/emd_ebpf_prebuild");