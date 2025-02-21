# emd
The eBPF memory dumper is able to dump the physical memory on a linux machine, using an eBPF filter.  
This works even the kernel is in lock down mode. 

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. bpf-linker: `cargo install bpf-linker`

## build

```bash
cargo build --release
```

## usage
```
sudo ./emd -o output-file.bin
```

to show all options, you can use
```
./emd -h
```
