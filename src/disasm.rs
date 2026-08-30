//! EKI Code 段的 objdump 风格反汇编。
//!
//! EKI 不是 ELF。本模块先通过 ELM 解析器验证镜像，再按内核的运行时段布局生成临时
//! ELF64 视图，最后调用 GNU 或 LLVM objdump。临时视图不会写回 EKI，也不会执行重定位。

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use elm::{
    ELM_EKI_BLOCK_DESC_SIZE, ELM_EKI_HEADER_SIZE, ElmEbiArch, ElmEbiImage, ElmEbiSegmentKind,
    ElmEkiVariantRecord, parse_eki_image, parse_eki_variants,
};

const PAGE_SIZE: u64 = 4096;
const ELF64_HEADER_SIZE: usize = 64;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_SYMBOL_SIZE: usize = 24;
const ELF_ET_EXEC: u16 = 2;
const ELF_SHT_SYMTAB: u32 = 2;
const ELF_SHT_STRTAB: u32 = 3;
const ELF_SHF_ALLOC: u64 = 1 << 1;
const ELF_SHF_EXECINSTR: u64 = 1 << 2;
const ELF_STB_GLOBAL: u8 = 1;
const ELF_STT_FUNC: u8 = 2;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_MACHINE_RISCV: u16 = 243;
const ELF_MACHINE_LOONGARCH: u16 = 258;
const EKI_BLOCK_VARIANT_IMAGE: u32 = 23;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    input: PathBuf,
    variant: Option<usize>,
    segment: Option<u32>,
    arch: Option<ElmEbiArch>,
    base_address: u64,
    start_address: Option<u64>,
    stop_address: Option<u64>,
    disassembler_options: Vec<String>,
    symbols: Vec<String>,
    no_show_raw_insn: bool,
    disassemble_zeroes: bool,
    disassemble_all: bool,
    tool: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: PathBuf::new(),
            variant: None,
            segment: None,
            arch: None,
            base_address: 0,
            start_address: None,
            stop_address: None,
            disassembler_options: Vec::new(),
            symbols: Vec::new(),
            no_show_raw_insn: false,
            disassemble_zeroes: false,
            disassemble_all: false,
            tool: None,
        }
    }
}

#[derive(Debug, Clone)]
struct CodeSection {
    segment_index: u32,
    runtime_offset: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CodeSymbol {
    name: String,
    section_index: usize,
    value: u64,
    size: u64,
}

#[derive(Debug, Clone)]
struct ImageView {
    arch: ElmEbiArch,
    base_address: u64,
    sections: Vec<CodeSection>,
    symbols: Vec<CodeSymbol>,
    entry: u64,
}

#[derive(Debug, Clone)]
struct ImageChoice {
    variant_index: Option<usize>,
    record: Option<ElmEkiVariantRecord>,
    image: ElmEbiImage,
    arch: ElmEbiArch,
}

#[derive(Debug)]
struct TemporaryElf {
    path: PathBuf,
}

impl Drop for TemporaryElf {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let options = parse_options(args)?;
    let bytes = fs::read(&options.input)
        .map_err(|error| format!("读取 {} 失败: {error}", options.input.display()))?;
    let choices = load_choices(&bytes, &options)?;
    for (index, choice) in choices.iter().enumerate() {
        if index != 0 {
            println!();
        }
        let view = build_image_view(&choice.image, choice.arch, &options)?;
        print_banner(&options.input, choice, &view);
        let elf = build_elf(&view)?;
        let temporary = write_temporary_elf(&elf)?;
        let output = invoke_objdump(&temporary.path, &options, choice.arch)?;
        print_objdump_output(&output, &temporary.path, &options.input);
    }
    Ok(())
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut positional = Vec::new();
    let mut index = 0usize;
    let mut after_separator = false;
    let mut explicit_all = false;

    while index < args.len() {
        let argument = &args[index];
        if after_separator {
            positional.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            after_separator = true;
            index += 1;
            continue;
        }
        match argument.as_str() {
            "-d" | "--disassemble" => {
                options.disassemble_all = false;
                index += 1;
            }
            "-D" | "--disassemble-all" => {
                options.disassemble_all = true;
                index += 1;
            }
            "-z" | "--disassemble-zeroes" => {
                options.disassemble_zeroes = true;
                index += 1;
            }
            "-w" | "--wide" => index += 1,
            "-M" => {
                let value = option_value(args, index + 1, argument)?;
                options.disassembler_options.push(value.to_string());
                index += 2;
            }
            "--all" => {
                explicit_all = true;
                index += 1;
            }
            "--no-show-raw-insn" => {
                options.no_show_raw_insn = true;
                index += 1;
            }
            "--variant" => {
                let value = option_value(args, index + 1, argument)?;
                options.variant = Some(parse_usize(value, "variant")?);
                index += 2;
            }
            "--segment" | "--section" => {
                let value = option_value(args, index + 1, argument)?;
                options.segment = Some(parse_segment_index(value)?);
                index += 2;
            }
            "--arch" => {
                let value = option_value(args, index + 1, argument)?;
                options.arch = Some(parse_arch(value)?);
                index += 2;
            }
            "--base-address" | "--adjust-vma" => {
                let value = option_value(args, index + 1, argument)?;
                options.base_address = parse_number(value, "地址")?;
                index += 2;
            }
            "--start-address" => {
                let value = option_value(args, index + 1, argument)?;
                options.start_address = Some(parse_number(value, "start-address")?);
                index += 2;
            }
            "--stop-address" => {
                let value = option_value(args, index + 1, argument)?;
                options.stop_address = Some(parse_number(value, "stop-address")?);
                index += 2;
            }
            "--disassembler-options" => {
                let value = option_value(args, index + 1, argument)?;
                options.disassembler_options.push(value.to_string());
                index += 2;
            }
            "--symbol" => {
                let value = option_value(args, index + 1, argument)?;
                if value.is_empty() {
                    return Err("--symbol 不能为空".to_string());
                }
                options.symbols.push(value.to_string());
                index += 2;
            }
            "--disassemble-symbols" => {
                let value = option_value(args, index + 1, argument)?;
                parse_symbol_list(value, &mut options.symbols)?;
                index += 2;
            }
            "--tool" => {
                let value = option_value(args, index + 1, argument)?;
                options.tool = Some(PathBuf::from(value));
                index += 2;
            }
            "-h" | "--help" => {
                return Err("请使用 cargo elm objdump --help 查看帮助".to_string());
            }
            argument if argument.starts_with("-M") && argument.len() > 2 => {
                options.disassembler_options.push(argument[2..].to_string());
                index += 1;
            }
            argument if argument.starts_with("--") => {
                let (name, inline) = split_long_option(argument);
                if name == "--disassemble" {
                    if let Some(symbol) = inline {
                        if symbol.is_empty() {
                            return Err("--disassemble 的符号名不能为空".to_string());
                        }
                        options.symbols.push(symbol.to_string());
                    } else {
                        options.disassemble_all = false;
                    }
                    index += 1;
                    continue;
                }
                if inline.is_none() && matches!(name, "--disassemble" | "--disassemble-all") {
                    options.disassemble_all = name == "--disassemble-all";
                    index += 1;
                    continue;
                }
                if inline.is_none() && matches!(name, "--disassemble-zeroes" | "--wide") {
                    if name == "--disassemble-zeroes" {
                        options.disassemble_zeroes = true;
                    }
                    index += 1;
                    continue;
                }
                let value = inline.ok_or_else(|| format!("未知或缺少值的 objdump 参数: {name}"))?;
                match name {
                    "--variant" => options.variant = Some(parse_usize(value, "variant")?),
                    "--segment" | "--section" => {
                        options.segment = Some(parse_segment_index(value)?)
                    }
                    "--arch" => options.arch = Some(parse_arch(value)?),
                    "--base-address" | "--adjust-vma" => {
                        options.base_address = parse_number(value, "地址")?
                    }
                    "--start-address" => {
                        options.start_address = Some(parse_number(value, "start-address")?)
                    }
                    "--stop-address" => {
                        options.stop_address = Some(parse_number(value, "stop-address")?)
                    }
                    "--disassembler-options" => {
                        options.disassembler_options.push(value.to_string())
                    }
                    "--symbol" => {
                        if value.is_empty() {
                            return Err("--symbol 不能为空".to_string());
                        }
                        options.symbols.push(value.to_string());
                    }
                    "--disassemble-symbols" => parse_symbol_list(value, &mut options.symbols)?,
                    "--tool" => options.tool = Some(PathBuf::from(value)),
                    _ => return Err(format!("未知 objdump 参数: {name}")),
                }
                index += 1;
            }
            argument if argument.starts_with('-') => {
                return Err(format!("未知 objdump 参数: {argument}"));
            }
            _ => {
                positional.push(argument.clone());
                index += 1;
            }
        }
    }

    if positional.len() != 1 {
        return Err("objdump 需要且只能接受一个 EKI 文件路径".to_string());
    }
    options.input = PathBuf::from(&positional[0]);
    if explicit_all && options.variant.is_some() {
        return Err("--all 不能与 --variant 同时使用".to_string());
    }
    if let (Some(start), Some(stop)) = (options.start_address, options.stop_address)
        && start >= stop
    {
        return Err("--start-address 必须小于 --stop-address".to_string());
    }
    Ok(options)
}

fn option_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .filter(|value| !value.starts_with('-') || is_numeric_value(value))
        .ok_or_else(|| format!("{option} 需要一个值"))
}

fn split_long_option(argument: &str) -> (&str, Option<&str>) {
    argument
        .split_once('=')
        .map_or((argument, None), |(name, value)| (name, Some(value)))
}

fn parse_symbol_list(value: &str, symbols: &mut Vec<String>) -> Result<(), String> {
    if value.is_empty() {
        return Err("符号名不能为空".to_string());
    }
    for symbol in value.split(',') {
        if symbol.is_empty() {
            return Err(format!("无效的符号列表: {value}"));
        }
        symbols.push(symbol.to_string());
    }
    Ok(())
}

fn is_numeric_value(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit()))
        || (!value.is_empty() && value.chars().all(|c| c.is_ascii_digit()))
}

fn parse_number(value: &str, name: &str) -> Result<u64, String> {
    let normalized = value.replace('_', "");
    let result = if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        normalized.parse::<u64>()
    };
    result.map_err(|_| format!("无效的 {name}: {value}"))
}

fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
    usize::try_from(parse_number(value, name)?)
        .map_err(|_| format!("{name} 超出宿主地址空间: {value}"))
}

fn parse_segment_index(value: &str) -> Result<u32, String> {
    let value = value
        .strip_prefix(".text.segment")
        .or_else(|| value.strip_prefix(".text.seg"))
        .or_else(|| value.strip_prefix("segment"))
        .unwrap_or(value);
    u32::try_from(parse_number(value, "segment")?)
        .map_err(|_| format!("segment 索引超出 u32: {value}"))
}

fn parse_arch(value: &str) -> Result<ElmEbiArch, String> {
    match value.to_ascii_lowercase().as_str() {
        "any" => Ok(ElmEbiArch::Any),
        "x86_64" | "x86-64" | "amd64" | "x86_64-unknown-none" => Ok(ElmEbiArch::X86_64),
        "riscv64" | "riscv64gc" | "riscv" | "riscv64gc-unknown-none-elf" => Ok(ElmEbiArch::Riscv64),
        "loongarch64" | "loong64" | "loongarch" | "loongarch64-unknown-none" => {
            Ok(ElmEbiArch::LoongArch64)
        }
        _ => Err(format!(
            "未知架构 {value:?}；可选值为 x86_64、riscv64、loongarch64 或 any"
        )),
    }
}

fn load_choices(bytes: &[u8], options: &Options) -> Result<Vec<ImageChoice>, String> {
    let records = parse_eki_variants(bytes)
        .map_err(|status| format!("EKI 变体目录或完整性校验失败: {status:?}"))?;
    if records.is_empty() {
        if options.variant.is_some() {
            return Err("单变体 EKI 不能使用 --variant".to_string());
        }
        let image = parse_eki_image(bytes).map_err(|status| format!("EKI 解析失败: {status:?}"))?;
        let arch = resolve_arch(image.unit.target.arch, options.arch)?;
        return Ok(vec![ImageChoice {
            variant_index: None,
            record: None,
            image,
            arch,
        }]);
    }

    let selected_indices: Vec<usize> = if let Some(index) = options.variant {
        if index >= records.len() {
            return Err(format!(
                "变体索引 {index} 超出范围；文件包含 {} 个变体",
                records.len()
            ));
        }
        vec![index]
    } else {
        (0..records.len()).collect()
    };
    let mut choices = Vec::new();
    for index in selected_indices {
        let record = records[index];
        if let Some(requested) = options.arch
            && requested != ElmEbiArch::Any
            && record.arch != ElmEbiArch::Any
            && record.arch != requested
        {
            continue;
        }
        let payload = variant_payload(bytes, &record)?;
        let image = parse_eki_image(payload)
            .map_err(|status| format!("变体 {index} 解析失败: {status:?}"))?;
        let arch = resolve_arch(image.unit.target.arch, options.arch)?;
        choices.push(ImageChoice {
            variant_index: Some(index),
            record: Some(record),
            image,
            arch,
        });
    }
    if choices.is_empty() {
        return Err("没有匹配 --arch 的变体".to_string());
    }
    Ok(choices)
}

fn resolve_arch(
    image_arch: ElmEbiArch,
    requested: Option<ElmEbiArch>,
) -> Result<ElmEbiArch, String> {
    match (image_arch, requested) {
        (ElmEbiArch::Any, Some(ElmEbiArch::Any) | None) => {
            Err("目标架构为 any；必须使用 --arch 指定具体架构".to_string())
        }
        (ElmEbiArch::Any, Some(arch)) => Ok(arch),
        (arch, Some(requested)) if requested != ElmEbiArch::Any && arch != requested => {
            Err(format!(
                "EKI 架构为 {}，不能按 {} 反汇编",
                arch_name(arch),
                arch_name(requested)
            ))
        }
        (arch, _) => Ok(arch),
    }
}

fn variant_payload<'a>(bytes: &'a [u8], record: &ElmEkiVariantRecord) -> Result<&'a [u8], String> {
    if bytes.len() < ELM_EKI_HEADER_SIZE {
        return Err("EKI header 不完整".to_string());
    }
    let block_table_offset = usize::try_from(read_u64(bytes, 24)?)
        .map_err(|_| "EKI block table offset 超出宿主地址空间".to_string())?;
    let block_count =
        usize::try_from(read_u32(bytes, 48)?).map_err(|_| "EKI block count 无效".to_string())?;
    let block_index =
        usize::try_from(record.block_index).map_err(|_| "EKI 变体 block index 无效".to_string())?;
    if block_index >= block_count {
        return Err(format!("变体引用不存在的 block {block_index}"));
    }
    let descriptor_offset = block_table_offset
        .checked_add(
            block_index
                .checked_mul(ELM_EKI_BLOCK_DESC_SIZE)
                .ok_or_else(|| "EKI block descriptor offset 溢出".to_string())?,
        )
        .ok_or_else(|| "EKI block descriptor offset 溢出".to_string())?;
    if read_u32(bytes, descriptor_offset)? != EKI_BLOCK_VARIANT_IMAGE {
        return Err(format!("变体 block {block_index} 不是 VariantImage"));
    }
    let payload_offset = usize::try_from(read_u64(bytes, descriptor_offset + 8)?)
        .map_err(|_| "变体 payload offset 超出宿主地址空间".to_string())?;
    let payload_size = usize::try_from(read_u64(bytes, descriptor_offset + 16)?)
        .map_err(|_| "变体 payload size 超出宿主地址空间".to_string())?;
    let end = payload_offset
        .checked_add(payload_size)
        .ok_or_else(|| "变体 payload range 溢出".to_string())?;
    bytes
        .get(payload_offset..end)
        .ok_or_else(|| "变体 payload 超出 EKI 文件".to_string())
}

fn build_image_view(
    image: &ElmEbiImage,
    arch: ElmEbiArch,
    options: &Options,
) -> Result<ImageView, String> {
    let mut cursor = 0u64;
    let mut sections = Vec::new();
    for (segment_index, segment) in image.unit.segments.iter().enumerate() {
        if !matches!(
            segment.kind,
            ElmEbiSegmentKind::Code
                | ElmEbiSegmentKind::ReadOnlyData
                | ElmEbiSegmentKind::Data
                | ElmEbiSegmentKind::Bss
        ) {
            continue;
        }
        cursor = align_up(cursor, PAGE_SIZE).ok_or_else(|| "EKI 运行时段布局溢出".to_string())?;
        let mapped_size = align_up(segment.mem_size, PAGE_SIZE)
            .ok_or_else(|| "EKI 段大小对齐溢出".to_string())?;
        if segment.kind == ElmEbiSegmentKind::Code
            && options
                .segment
                .is_none_or(|selected| selected == segment_index as u32)
        {
            let payload = image
                .payloads
                .iter()
                .find(|payload| {
                    payload.segment_index == segment_index as u32
                        && payload.kind == ElmEbiSegmentKind::Code
                })
                .ok_or_else(|| format!("Code 段 {segment_index} 缺少 payload"))?;
            let file_size = usize::try_from(payload.file_size)
                .map_err(|_| format!("Code 段 {segment_index} file_size 超出宿主地址空间"))?;
            if payload.bytes.len() != file_size
                || payload.file_size != segment.file_size
                || payload.mem_size != segment.mem_size
            {
                return Err(format!("Code 段 {segment_index} 的 payload 尺寸不一致"));
            }
            let end = options
                .base_address
                .checked_add(cursor)
                .and_then(|value| value.checked_add(payload.bytes.len() as u64))
                .ok_or_else(|| "EKI 地址加法溢出".to_string())?;
            let _ = end;
            sections.push(CodeSection {
                segment_index: segment_index as u32,
                runtime_offset: cursor,
                bytes: payload.bytes.clone(),
            });
        }
        cursor = cursor
            .checked_add(mapped_size)
            .ok_or_else(|| "EKI 运行时段总大小溢出".to_string())?;
        // The displayed address is base + runtime offset.  Check the whole
        // accumulated layout, not just the bytes of selected Code sections.
        options
            .base_address
            .checked_add(cursor)
            .ok_or_else(|| "EKI 基址与运行时布局相加溢出".to_string())?;
    }
    if sections.is_empty() {
        return Err(options.segment.map_or_else(
            || "EKI 没有可反汇编的 Code 段".to_string(),
            |segment| format!("找不到 Code 段 {segment}"),
        ));
    }

    let mut symbols = Vec::new();
    for symbol in &image.symbol_locations {
        let Some(section_index) = sections
            .iter()
            .position(|section| section.segment_index == symbol.segment_index)
        else {
            continue;
        };
        let section = &sections[section_index];
        let end = symbol
            .offset
            .checked_add(symbol.size)
            .ok_or_else(|| format!("符号 {} 的范围溢出", symbol.name))?;
        if end > section.bytes.len() as u64 {
            return Err(format!("符号 {} 超出 Code payload", symbol.name));
        }
        let value = section
            .runtime_offset
            .checked_add(symbol.offset)
            .ok_or_else(|| format!("符号 {} 地址溢出", symbol.name))?;
        symbols.push(CodeSymbol {
            name: symbol.name.clone(),
            section_index,
            value,
            size: symbol.size,
        });
    }
    if !options.symbols.is_empty() {
        for requested in &options.symbols {
            if !symbols.iter().any(|symbol| &symbol.name == requested) {
                return Err(format!("未找到 Code 符号 {requested:?}"));
            }
        }
    }
    let entry = image
        .unit
        .entry
        .as_ref()
        .and_then(|entry| symbols.iter().find(|symbol| symbol.name == entry.symbol))
        .map_or(sections[0].runtime_offset, |symbol| symbol.value);
    Ok(ImageView {
        arch,
        base_address: options.base_address,
        sections,
        symbols,
        entry,
    })
}

fn print_banner(path: &Path, choice: &ImageChoice, view: &ImageView) {
    println!("file format eki");
    println!("input: {}", path.display());
    println!("architecture: {}", arch_name(view.arch));
    println!("image base: 0x{:x}", view.base_address);
    if let Some(index) = choice.variant_index {
        println!(
            "variant: {index} priority={}",
            choice.record.map_or(0, |record| record.priority)
        );
    }
    for (index, section) in view.sections.iter().enumerate() {
        let address = view.base_address.saturating_add(section.runtime_offset);
        println!(
            "section[{index}]: .text.seg{} address=0x{address:x} size=0x{:x}",
            section.segment_index,
            section.bytes.len()
        );
    }
    println!("symbols: {}", view.symbols.len());
}

fn arch_name(arch: ElmEbiArch) -> &'static str {
    match arch {
        ElmEbiArch::Any => "any",
        ElmEbiArch::Riscv64 => "riscv64",
        ElmEbiArch::LoongArch64 => "loongarch64",
        ElmEbiArch::X86_64 => "x86_64",
    }
}

fn machine_for_arch(arch: ElmEbiArch) -> Result<u16, String> {
    match arch {
        ElmEbiArch::X86_64 => Ok(ELF_MACHINE_X86_64),
        ElmEbiArch::Riscv64 => Ok(ELF_MACHINE_RISCV),
        ElmEbiArch::LoongArch64 => Ok(ELF_MACHINE_LOONGARCH),
        ElmEbiArch::Any => Err("不能为 any 架构生成 ELF".to_string()),
    }
}

#[derive(Debug, Clone)]
struct SectionHeader {
    name: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
}

fn build_elf(view: &ImageView) -> Result<Vec<u8>, String> {
    let machine = machine_for_arch(view.arch)?;
    let mut shstrtab = vec![0u8];
    let mut section_name_offsets = Vec::with_capacity(view.sections.len());
    for section in &view.sections {
        section_name_offsets.push(append_string(
            &mut shstrtab,
            &format!(".text.seg{}", section.segment_index),
        )?);
    }
    let symtab_name = append_string(&mut shstrtab, ".symtab")?;
    let strtab_name = append_string(&mut shstrtab, ".strtab")?;
    let shstrtab_name = append_string(&mut shstrtab, ".shstrtab")?;

    let mut strtab = vec![0u8];
    let mut string_offsets = BTreeMap::new();
    for symbol in &view.symbols {
        if !string_offsets.contains_key(&symbol.name) {
            let offset = append_string(&mut strtab, &symbol.name)?;
            string_offsets.insert(symbol.name.clone(), offset);
        }
    }

    let symtab_index = 1usize + view.sections.len();
    let strtab_index = symtab_index + 1;
    let shstrtab_index = symtab_index + 2;
    let section_count = shstrtab_index + 1;
    let mut symtab = vec![0u8; ELF64_SYMBOL_SIZE];
    for symbol in &view.symbols {
        let name = *string_offsets
            .get(&symbol.name)
            .ok_or_else(|| format!("符号字符串缺失: {}", symbol.name))?;
        let section = u16::try_from(1usize + symbol.section_index)
            .map_err(|_| "Code section 数量超出 ELF 限制".to_string())?;
        let offset = symtab.len();
        symtab.resize(
            offset
                .checked_add(ELF64_SYMBOL_SIZE)
                .ok_or_else(|| "ELF symbol table 溢出".to_string())?,
            0,
        );
        write_u32(&mut symtab, offset, name);
        symtab[offset + 4] = ELF_STB_GLOBAL << 4 | ELF_STT_FUNC;
        write_u16(&mut symtab, offset + 6, section);
        write_u64(&mut symtab, offset + 8, symbol.value);
        write_u64(&mut symtab, offset + 16, symbol.size);
    }

    let mut output = vec![0u8; ELF64_HEADER_SIZE];
    let mut headers = Vec::with_capacity(section_count);
    headers.push(SectionHeader {
        name: 0,
        section_type: 0,
        flags: 0,
        address: 0,
        offset: 0,
        size: 0,
        link: 0,
        info: 0,
        addralign: 0,
        entsize: 0,
    });
    for (index, section) in view.sections.iter().enumerate() {
        align_vec(&mut output, 0x1000);
        let offset = output.len();
        output.extend_from_slice(&section.bytes);
        headers.push(SectionHeader {
            name: section_name_offsets[index],
            section_type: 1,
            flags: ELF_SHF_ALLOC | ELF_SHF_EXECINSTR,
            address: section.runtime_offset,
            offset: offset as u64,
            size: section.bytes.len() as u64,
            link: 0,
            info: 0,
            addralign: 1,
            entsize: 0,
        });
    }

    align_vec(&mut output, 8);
    let symtab_offset = output.len();
    output.extend_from_slice(&symtab);
    headers.push(SectionHeader {
        name: symtab_name,
        section_type: ELF_SHT_SYMTAB,
        flags: 0,
        address: 0,
        offset: symtab_offset as u64,
        size: symtab.len() as u64,
        link: u32::try_from(strtab_index).map_err(|_| "ELF section index 溢出".to_string())?,
        info: 1,
        addralign: 8,
        entsize: ELF64_SYMBOL_SIZE as u64,
    });

    let strtab_offset = output.len();
    output.extend_from_slice(&strtab);
    headers.push(SectionHeader {
        name: strtab_name,
        section_type: ELF_SHT_STRTAB,
        flags: 0,
        address: 0,
        offset: strtab_offset as u64,
        size: strtab.len() as u64,
        link: 0,
        info: 0,
        addralign: 1,
        entsize: 0,
    });

    let shstrtab_offset = output.len();
    output.extend_from_slice(&shstrtab);
    headers.push(SectionHeader {
        name: shstrtab_name,
        section_type: ELF_SHT_STRTAB,
        flags: 0,
        address: 0,
        offset: shstrtab_offset as u64,
        size: shstrtab.len() as u64,
        link: 0,
        info: 0,
        addralign: 1,
        entsize: 0,
    });

    align_vec(&mut output, 8);
    let section_headers_offset = output.len();
    output.resize(
        section_headers_offset
            .checked_add(headers.len() * ELF64_SECTION_HEADER_SIZE)
            .ok_or_else(|| "ELF section header table 溢出".to_string())?,
        0,
    );
    for (index, header) in headers.iter().enumerate() {
        let offset = section_headers_offset + index * ELF64_SECTION_HEADER_SIZE;
        write_u32(&mut output, offset, header.name);
        write_u32(&mut output, offset + 4, header.section_type);
        write_u64(&mut output, offset + 8, header.flags);
        write_u64(&mut output, offset + 16, header.address);
        write_u64(&mut output, offset + 24, header.offset);
        write_u64(&mut output, offset + 32, header.size);
        write_u32(&mut output, offset + 40, header.link);
        write_u32(&mut output, offset + 44, header.info);
        write_u64(&mut output, offset + 48, header.addralign);
        write_u64(&mut output, offset + 56, header.entsize);
    }

    output[0..4].copy_from_slice(b"\x7fELF");
    output[4] = 2;
    output[5] = 1;
    output[6] = 1;
    write_u16(&mut output, 16, ELF_ET_EXEC);
    write_u16(&mut output, 18, machine);
    write_u32(&mut output, 20, 1);
    write_u64(&mut output, 24, view.entry);
    write_u64(&mut output, 40, section_headers_offset as u64);
    write_u16(&mut output, 52, ELF64_HEADER_SIZE as u16);
    write_u16(&mut output, 58, ELF64_SECTION_HEADER_SIZE as u16);
    write_u16(
        &mut output,
        60,
        u16::try_from(headers.len()).map_err(|_| "ELF section 数量超出 u16".to_string())?,
    );
    write_u16(
        &mut output,
        62,
        u16::try_from(shstrtab_index).map_err(|_| "ELF shstrtab index 超出 u16".to_string())?,
    );
    Ok(output)
}

fn append_string(table: &mut Vec<u8>, value: &str) -> Result<u32, String> {
    let offset = u32::try_from(table.len()).map_err(|_| "ELF string table 超出 u32".to_string())?;
    table.extend_from_slice(value.as_bytes());
    table.push(0);
    Ok(offset)
}

fn align_vec(output: &mut Vec<u8>, alignment: usize) {
    let alignment = alignment.max(1);
    let remainder = output.len() % alignment;
    if remainder != 0 {
        output.resize(output.len() + alignment - remainder, 0);
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let alignment = alignment.max(1);
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

fn write_temporary_elf(bytes: &[u8]) -> Result<TemporaryElf, String> {
    let directory = env::temp_dir();
    for attempt in 0..32u32 {
        let serial = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            "cargo-elm-objdump-{}-{}-{}.elf",
            std::process::id(),
            serial,
            attempt
        ));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("创建临时 ELF {} 失败: {error}", path.display())),
        };
        if let Err(error) = file.write_all(bytes) {
            let _ = fs::remove_file(&path);
            return Err(format!("写入临时 ELF {} 失败: {error}", path.display()));
        }
        return Ok(TemporaryElf { path });
    }
    Err("无法分配唯一的临时 ELF 路径".to_string())
}

fn invoke_objdump(path: &Path, options: &Options, arch: ElmEbiArch) -> Result<String, String> {
    let tool = select_tool(options.tool.as_deref(), arch)?;
    // GNU objdump spells symbol selection --disassemble=<name>, while LLVM
    // accepts --disassemble-symbols=<name>.  Run one GNU invocation per
    // requested symbol so a valid EKI --symbol filter never becomes an
    // unknown command-line option.
    if !options.symbols.is_empty() && !tool_is_llvm(&tool) {
        let mut outputs = Vec::with_capacity(options.symbols.len());
        for symbol in &options.symbols {
            outputs.push(invoke_objdump_once(
                path,
                options,
                arch,
                &tool,
                Some(symbol.as_str()),
            )?);
        }
        return Ok(outputs.join("\n"));
    }
    if tool_is_llvm(&tool) && !options.symbols.is_empty() {
        let symbols = options.symbols.join(",");
        return invoke_objdump_once(path, options, arch, &tool, Some(&symbols));
    }
    invoke_objdump_once(path, options, arch, &tool, None)
}

fn invoke_objdump_once(
    path: &Path,
    options: &Options,
    arch: ElmEbiArch,
    tool: &Path,
    symbol: Option<&str>,
) -> Result<String, String> {
    let mut command = Command::new(tool);
    if options.disassemble_all && symbol.is_none() {
        command.arg("--disassemble-all");
    } else {
        command.arg("--disassemble");
    }
    command.arg("--wide");
    if options.disassemble_zeroes {
        command.arg("--disassemble-zeroes");
    }
    if options.no_show_raw_insn {
        command.arg("--no-show-raw-insn");
    }
    command.arg(format!("--adjust-vma=0x{:x}", options.base_address));
    if let Some(start) = options.start_address {
        command.arg(format!("--start-address=0x{start:x}"));
    }
    if let Some(stop) = options.stop_address {
        command.arg(format!("--stop-address=0x{stop:x}"));
    }
    for option in &options.disassembler_options {
        command.arg(format!("--disassembler-options={option}"));
    }
    if let Some(symbol) = symbol {
        if tool_is_llvm(tool) {
            command.arg(format!("--disassemble-symbols={symbol}"));
        } else {
            command.arg(format!("--disassemble={symbol}"));
        }
    }
    command.arg(path);
    let output = command
        .output()
        .map_err(|error| format!("启动 objdump {} 失败: {error}", tool.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "objdump {} 无法反汇编 {}: {}",
            tool.display(),
            arch_name(arch),
            stderr.trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("objdump {} 输出不是 UTF-8", tool.display()))
}

fn tool_is_llvm(path: &Path) -> bool {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().contains("llvm"))
    {
        return true;
    }
    Command::new(path)
        .arg("--version")
        .output()
        .is_ok_and(|output| {
            String::from_utf8_lossy(&output.stdout).contains("LLVM")
                || String::from_utf8_lossy(&output.stderr).contains("LLVM")
        })
}

fn select_tool(explicit: Option<&Path>, arch: ElmEbiArch) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = env::var_os("ELM_OBJDUMP").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let candidates: &[&str] = match arch {
        ElmEbiArch::X86_64 => &["objdump", "llvm-objdump", "x86_64-linux-gnu-objdump"],
        ElmEbiArch::Riscv64 => &["riscv64-linux-gnu-objdump", "llvm-objdump"],
        ElmEbiArch::LoongArch64 => &["loongarch64-linux-gnu-objdump", "llvm-objdump"],
        ElmEbiArch::Any => return Err("objdump 需要具体目标架构".to_string()),
    };
    candidates
        .iter()
        .find(|candidate| command_available(candidate))
        .map(PathBuf::from)
        .ok_or_else(|| {
            format!(
                "未找到支持 {} 的 GNU/LLVM objdump；可用 --tool 指定路径",
                arch_name(arch)
            )
        })
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn print_objdump_output(output: &str, temporary: &Path, input: &Path) {
    let temporary = temporary.to_string_lossy();
    let input = input.to_string_lossy();
    let output = output.replace(temporary.as_ref(), input.as_ref());
    for line in output.lines() {
        if line.contains("file format ") {
            continue;
        }
        println!("{line}");
    }
}

#[cfg(test)]
fn normalized_objdump_output(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|line| !line.contains("file format "))
        .collect()
}

#[cfg(test)]
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| "EKI integer offset 溢出".to_string())?;
    let bytes = bytes
        .get(offset..end)
        .ok_or_else(|| "EKI integer 超出文件".to_string())?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "EKI integer offset 溢出".to_string())?;
    let bytes = bytes
        .get(offset..end)
        .ok_or_else(|| "EKI integer 超出文件".to_string())?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| "EKI integer offset 溢出".to_string())?;
    let bytes = bytes
        .get(offset..end)
        .ok_or_else(|| "EKI integer 超出文件".to_string())?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_view() -> ImageView {
        ImageView {
            arch: ElmEbiArch::X86_64,
            base_address: 0,
            sections: vec![CodeSection {
                segment_index: 0,
                runtime_offset: 0,
                bytes: vec![0x55, 0x48, 0x89, 0xe5, 0xc3],
            }],
            symbols: vec![CodeSymbol {
                name: "demo_entry".to_string(),
                section_index: 0,
                value: 0,
                size: 5,
            }],
            entry: 0,
        }
    }

    #[test]
    fn parses_objdump_compatible_options() {
        let args = vec![
            "-d".to_string(),
            "module.eki".to_string(),
            "-Mintel".to_string(),
            "--base-address=0x400000".to_string(),
            "--start-address".to_string(),
            "0x400000".to_string(),
            "--stop-address=0x400100".to_string(),
            "--symbol".to_string(),
            "demo_entry".to_string(),
            "--no-show-raw-insn".to_string(),
        ];
        let options = parse_options(&args).unwrap();
        assert_eq!(options.input, PathBuf::from("module.eki"));
        assert_eq!(options.base_address, 0x400000);
        assert_eq!(options.start_address, Some(0x400000));
        assert_eq!(options.stop_address, Some(0x400100));
        assert_eq!(options.disassembler_options, vec!["intel"]);
        assert_eq!(options.symbols, vec!["demo_entry"]);
        assert!(options.no_show_raw_insn);
    }

    #[test]
    fn parses_disassemble_all_and_long_compatibility_flags() {
        let args = vec![
            "module.eki".to_string(),
            "--disassemble-all".to_string(),
            "--disassemble-zeroes".to_string(),
            "--wide".to_string(),
            "-w".to_string(),
            "--section=.text.segment12".to_string(),
        ];
        let options = parse_options(&args).unwrap();
        assert!(options.disassemble_all);
        assert!(options.disassemble_zeroes);
        assert_eq!(options.segment, Some(12));

        let options = parse_options(&["-D".to_string(), "module.eki".to_string()]).unwrap();
        assert!(options.disassemble_all);

        let options = parse_options(&[
            "module.eki".to_string(),
            "--disassemble=demo_entry".to_string(),
        ])
        .unwrap();
        assert_eq!(options.symbols, vec!["demo_entry"]);

        let options = parse_options(&[
            "module.eki".to_string(),
            "--disassemble-symbols=demo_entry,other".to_string(),
        ])
        .unwrap();
        assert_eq!(options.symbols, vec!["demo_entry", "other"]);
    }

    #[test]
    fn rejects_conflicting_variant_selection() {
        let args = vec![
            "module.eki".to_string(),
            "--all".to_string(),
            "--variant".to_string(),
            "0".to_string(),
        ];
        let error = parse_options(&args).unwrap_err();
        assert!(error.contains("--all"));
    }

    #[test]
    fn builds_elf64_with_code_symbol() {
        let bytes = build_elf(&test_view()).unwrap();
        assert_eq!(&bytes[0..4], b"\x7fELF");
        assert_eq!(bytes[4], 2);
        assert_eq!(read_u16(&bytes, 18).unwrap(), ELF_MACHINE_X86_64);
        assert!(
            bytes
                .windows(b"demo_entry\0".len())
                .any(|window| window == b"demo_entry\0")
        );
        let temporary = write_temporary_elf(&bytes).unwrap();
        let output = invoke_objdump(
            &temporary.path,
            &Options {
                input: PathBuf::from("test.eki"),
                ..Options::default()
            },
            ElmEbiArch::X86_64,
        )
        .unwrap();
        assert!(output.contains("demo_entry"));
        assert!(output.contains("ret"));
    }

    #[test]
    fn gnu_objdump_symbol_filter_uses_supported_spelling() {
        if !command_available("objdump") {
            return;
        }
        let bytes = build_elf(&test_view()).unwrap();
        let temporary = write_temporary_elf(&bytes).unwrap();
        let output = invoke_objdump(
            &temporary.path,
            &Options {
                input: PathBuf::from("test.eki"),
                symbols: vec!["demo_entry".to_string()],
                tool: Some(PathBuf::from("objdump")),
                ..Options::default()
            },
            ElmEbiArch::X86_64,
        )
        .unwrap();
        assert!(output.contains("demo_entry"));
        assert!(output.contains("ret"));
    }

    #[test]
    fn llvm_objdump_symbol_filter_uses_supported_spelling() {
        if !command_available("llvm-objdump") {
            return;
        }
        let bytes = build_elf(&test_view()).unwrap();
        let temporary = write_temporary_elf(&bytes).unwrap();
        let output = invoke_objdump(
            &temporary.path,
            &Options {
                input: PathBuf::from("test.eki"),
                symbols: vec!["demo_entry".to_string()],
                tool: Some(PathBuf::from("llvm-objdump")),
                ..Options::default()
            },
            ElmEbiArch::X86_64,
        )
        .unwrap();
        assert!(output.contains("demo_entry"));
        assert!(output.contains("ret"));
    }

    #[test]
    fn aligns_runtime_offsets_to_pages() {
        assert_eq!(align_up(0, PAGE_SIZE), Some(0));
        assert_eq!(align_up(1, PAGE_SIZE), Some(PAGE_SIZE));
        assert_eq!(align_up(PAGE_SIZE, PAGE_SIZE), Some(PAGE_SIZE));
        assert_eq!(align_up(u64::MAX, PAGE_SIZE), None);
    }

    #[test]
    fn parses_arch_aliases() {
        assert_eq!(parse_arch("amd64").unwrap(), ElmEbiArch::X86_64);
        assert_eq!(parse_arch("riscv64gc").unwrap(), ElmEbiArch::Riscv64);
        assert_eq!(parse_arch("loong64").unwrap(), ElmEbiArch::LoongArch64);
        assert_eq!(
            parse_arch("riscv64gc-unknown-none-elf").unwrap(),
            ElmEbiArch::Riscv64
        );
        assert_eq!(
            parse_arch("loongarch64-unknown-none").unwrap(),
            ElmEbiArch::LoongArch64
        );
        assert_eq!(
            parse_arch("x86_64-unknown-none").unwrap(),
            ElmEbiArch::X86_64
        );
    }

    #[test]
    fn strips_gnu_and_llvm_synthetic_file_format_lines() {
        let gnu = "\ninput.eki:     file format elf64-x86-64\n\nDisassembly";
        let llvm = "\ninput.eki:\tfile format elf64-x86-64\n\nDisassembly";
        assert!(
            !normalized_objdump_output(gnu)
                .join("\n")
                .contains("file format")
        );
        assert!(
            !normalized_objdump_output(llvm)
                .join("\n")
                .contains("file format")
        );
    }
}
