use anyhow::Ok;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "build")]
    return build_ebpf();
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(feature = "build")]
fn build_ebpf() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context as _};
    use aya_build::cargo_metadata;

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "emd-ebpf-impl")
        .ok_or_else(|| anyhow!("emd-ebpf-impl package not found"))?;
    aya_build::build_ebpf([ebpf_package])
}