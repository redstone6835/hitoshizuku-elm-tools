//! Language-neutral ELM package and SDK generation.
//!
//! This module deliberately treats the EKI interface as data.  It never turns a
//! Rust ABI string into a callable function pointer: a language adapter must
//! explicitly describe every operation, and generated Rust code only exposes
//! checked operation descriptors and opaque resource handles.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use elm::sha256;
use serde::{Deserialize, Serialize};

use crate::kernel_interface::{KernelInterfaceManifest, KernelInterfaceSymbol};

const PACKAGE_SCHEMA_VERSION: u32 = 1;
const INTERFACE_SCHEMA_VERSION: u32 = 1;
const OPERATION_ID_DOMAIN: &[u8] = b"HITOSHIZUKU-ELM-OPERATION-V1\0";

/// Parsed and validated `LanguagePackage.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguagePackage {
    pub schema: u32,
    pub id: String,
    pub version: String,
    pub kind: String,
    pub backend: String,
    pub targets: Vec<String>,
    pub profile: String,
    pub eki: PathBuf,
    pub interface: PathBuf,
    pub capabilities: Vec<String>,
    pub max_handles: u32,
    pub max_dma_bytes: u64,
    pub max_pending_requests: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageDocument {
    package: RawPackage,
    capabilities: RawCapabilities,
    limits: RawLimits,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackage {
    schema: u32,
    id: String,
    version: String,
    kind: String,
    backend: String,
    targets: Vec<String>,
    profile: String,
    eki: String,
    interface: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapabilities {
    #[serde(default)]
    requested: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_handles: u32,
    max_dma_bytes: u64,
    max_pending_requests: u32,
}

impl LanguagePackage {
    pub fn load(path: &Path) -> Result<Self, String> {
        let input = fs::read_to_string(path)
            .map_err(|err| format!("读取 {} 失败: {err}", path.display()))?;
        let package = Self::parse(&input)?;
        validate_relative_path(&package.eki, "package.eki")?;
        validate_relative_path(&package.interface, "package.interface")?;
        Ok(package)
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let document: PackageDocument = toml::from_str(input)
            .map_err(|err| format!("解析 LanguagePackage.toml 失败: {err}"))?;
        if document.package.schema != PACKAGE_SCHEMA_VERSION {
            return Err(format!(
                "不支持的 LanguagePackage schema {}，当前版本为 {}",
                document.package.schema, PACKAGE_SCHEMA_VERSION
            ));
        }
        validate_identifier(&document.package.id, "package.id", 128)?;
        validate_version(&document.package.version, "package.version")?;
        validate_identifier(&document.package.kind, "package.kind", 32)?;
        if !matches!(
            document.package.kind.as_str(),
            "driver" | "service" | "filesystem" | "network" | "extension" | "other"
        ) {
            return Err(format!("未知 package.kind: {}", document.package.kind));
        }
        validate_identifier(&document.package.backend, "package.backend", 64)?;
        if document.package.targets.is_empty() {
            return Err("package.targets 不能为空".to_string());
        }
        let mut targets = Vec::with_capacity(document.package.targets.len());
        for target in document.package.targets {
            validate_target(&target)?;
            if !targets.iter().all(|item| item != &target) {
                return Err(format!("package.targets 重复项: {target}"));
            }
            targets.push(target);
        }
        validate_identifier(&document.package.profile, "package.profile", 64)?;
        validate_relative_string(&document.package.eki, "package.eki")?;
        validate_relative_string(&document.package.interface, "package.interface")?;
        let mut capabilities = Vec::with_capacity(document.capabilities.requested.len());
        for capability in document.capabilities.requested {
            validate_capability(&capability)?;
            if capabilities.iter().any(|item| item == &capability) {
                return Err(format!("capabilities.requested 重复项: {capability}"));
            }
            capabilities.push(capability);
        }
        if document.limits.max_handles == 0
            || document.limits.max_dma_bytes == 0
            || document.limits.max_pending_requests == 0
        {
            return Err("所有 limits 必须大于 0".to_string());
        }
        Ok(Self {
            schema: document.package.schema,
            id: document.package.id,
            version: document.package.version,
            kind: document.package.kind,
            backend: document.package.backend,
            targets,
            profile: document.package.profile,
            eki: PathBuf::from(document.package.eki),
            interface: PathBuf::from(document.package.interface),
            capabilities,
            max_handles: document.limits.max_handles,
            max_dma_bytes: document.limits.max_dma_bytes,
            max_pending_requests: document.limits.max_pending_requests,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationAdapter {
    pub api_path: String,
    pub wire: String,
    pub request: String,
    pub response: String,
    pub ownership: String,
    pub capability: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterDocument {
    #[serde(rename = "operation")]
    operations: Vec<RawOperationAdapter>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOperationAdapter {
    api_path: String,
    wire: String,
    request: String,
    response: String,
    ownership: String,
    capability: Option<String>,
}

impl OperationAdapter {
    pub fn load(path: &Path) -> Result<Vec<Self>, String> {
        let input = fs::read_to_string(path)
            .map_err(|err| format!("读取 {} 失败: {err}", path.display()))?;
        Self::parse(&input)
    }

    pub fn parse(input: &str) -> Result<Vec<Self>, String> {
        let document: AdapterDocument =
            toml::from_str(input).map_err(|err| format!("解析 LanguageBridge.toml 失败: {err}"))?;
        if document.operations.is_empty() {
            return Err("LanguageBridge.toml 至少需要一个 [[operation]]".to_string());
        }
        let mut output = Vec::with_capacity(document.operations.len());
        let mut paths = BTreeSet::new();
        for raw in document.operations {
            validate_api_path(&raw.api_path)?;
            validate_wire(&raw.wire)?;
            validate_type_name(&raw.request, "operation.request")?;
            validate_type_name(&raw.response, "operation.response")?;
            if !matches!(
                raw.ownership.as_str(),
                "none" | "borrowed" | "returns-owned" | "consumes" | "inout"
            ) {
                return Err(format!("未知 operation.ownership: {}", raw.ownership));
            }
            if let Some(capability) = &raw.capability {
                validate_capability(capability)?;
            }
            if !paths.insert(raw.api_path.clone()) {
                return Err(format!("重复 operation.api_path: {}", raw.api_path));
            }
            output.push(Self {
                api_path: raw.api_path,
                wire: raw.wire,
                request: raw.request,
                response: raw.response,
                ownership: raw.ownership,
                capability: raw.capability,
            });
        }
        output.sort_by(|left, right| left.api_path.cmp(&right.api_path));
        Ok(output)
    }
}

#[derive(Debug, Clone, Serialize)]
struct InterfaceSchema {
    schema: u32,
    package: SchemaPackage,
    interface: InterfaceIdentity,
    symbols: Vec<SchemaSymbol>,
    operations: Vec<SchemaOperation>,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaPackage {
    id: String,
    version: String,
    kind: String,
    backend: String,
    capabilities: Vec<String>,
    limits: SchemaLimits,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaLimits {
    max_handles: u32,
    max_dma_bytes: u64,
    max_pending_requests: u32,
}

#[derive(Debug, Clone, Serialize)]
struct InterfaceIdentity {
    target: String,
    profile: String,
    bridge_abi: u16,
    kernel_sha256: String,
    interface_sha256: String,
    source_sha256: String,
    framework_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaSymbol {
    api_path: String,
    item_path: String,
    link_name: String,
    contract: String,
    kind: u8,
    version: u32,
    capabilities: u64,
    rust_abi_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaOperation {
    id: String,
    api_path: String,
    wire: String,
    request: String,
    response: String,
    ownership: String,
    capability: Option<String>,
    symbol: SchemaOperationSymbol,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaOperationSymbol {
    link_name: String,
    contract: String,
    version: u32,
    rust_abi_sha256: String,
}

fn build_schema(
    interface: &KernelInterfaceManifest,
    package: Option<&LanguagePackage>,
    operations: &[OperationAdapter],
) -> Result<InterfaceSchema, String> {
    if let Some(package) = package {
        if !package
            .targets
            .iter()
            .any(|target| target == &interface.target)
        {
            return Err(format!(
                "package.targets 不包含接口目标 {}",
                interface.target
            ));
        }
        if package.profile != interface.profile {
            return Err(format!(
                "package.profile={} 与接口 profile={} 不一致",
                package.profile, interface.profile
            ));
        }
    }
    let mut symbols = interface
        .symbols
        .iter()
        .map(schema_symbol)
        .collect::<Vec<_>>();
    symbols.sort_by(|left, right| left.api_path.cmp(&right.api_path));
    let mut schema_operations = Vec::with_capacity(operations.len());
    let mut operation_ids = BTreeSet::new();
    for operation in operations {
        let symbol = interface
            .symbols
            .iter()
            .find(|symbol| symbol.api_path == operation.api_path)
            .ok_or_else(|| format!("adapter operation 未导出的 API: {}", operation.api_path))?;
        if let Some(capability) = &operation.capability {
            if let Some(package) = package {
                if !package.capabilities.iter().any(|item| item == capability) {
                    return Err(format!(
                        "operation {} 使用了 package 未声明的 capability {}",
                        operation.api_path, capability
                    ));
                }
            }
        }
        let id = operation_id(operation);
        if !operation_ids.insert(id) {
            return Err(format!("operation id 冲突: {}", operation.api_path));
        }
        schema_operations.push(SchemaOperation {
            id: hex_digest(&id),
            api_path: operation.api_path.clone(),
            wire: operation.wire.clone(),
            request: operation.request.clone(),
            response: operation.response.clone(),
            ownership: operation.ownership.clone(),
            capability: operation.capability.clone(),
            symbol: SchemaOperationSymbol {
                link_name: symbol.link_name.clone(),
                contract: symbol.contract.clone(),
                version: symbol.version,
                rust_abi_sha256: hex_digest(&symbol.rust_abi_hash),
            },
        });
    }
    let package = package.map_or_else(
        || SchemaPackage {
            id: "kernel.interface".to_string(),
            version: "0.0.0".to_string(),
            kind: "other".to_string(),
            backend: "rust".to_string(),
            capabilities: Vec::new(),
            limits: SchemaLimits {
                max_handles: 0,
                max_dma_bytes: 0,
                max_pending_requests: 0,
            },
        },
        |package| SchemaPackage {
            id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            backend: package.backend.clone(),
            capabilities: package.capabilities.clone(),
            limits: SchemaLimits {
                max_handles: package.max_handles,
                max_dma_bytes: package.max_dma_bytes,
                max_pending_requests: package.max_pending_requests,
            },
        },
    );
    Ok(InterfaceSchema {
        schema: INTERFACE_SCHEMA_VERSION,
        package,
        interface: InterfaceIdentity {
            target: interface.target.clone(),
            profile: interface.profile.clone(),
            bridge_abi: interface.bridge_abi_version,
            kernel_sha256: hex_digest(&interface.kernel_hash),
            interface_sha256: hex_digest(&interface.interface_hash),
            source_sha256: hex_digest(&interface.source_hash),
            framework_sha256: hex_digest(&interface.framework_hash),
        },
        symbols,
        operations: schema_operations,
    })
}

pub fn generate_interface_schema(
    interface_path: &Path,
    package_path: Option<&Path>,
    adapter_path: Option<&Path>,
    output: &Path,
) -> Result<(), String> {
    let interface = KernelInterfaceManifest::load(interface_path)?;
    let package = package_path
        .map(LanguagePackage::load)
        .transpose()
        .map_err(|err| err.to_string())?;
    let operations = adapter_path
        .map(OperationAdapter::load)
        .transpose()?
        .unwrap_or_default();
    let schema = build_schema(&interface, package.as_ref(), &operations)?;
    write_json(output, &schema)
}

pub fn generate_rust_sdk(
    interface_path: &Path,
    package_path: &Path,
    adapter_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let interface = KernelInterfaceManifest::load(interface_path)?;
    let package = LanguagePackage::load(package_path)?;
    let operations = OperationAdapter::load(adapter_path)?;
    let schema = build_schema(&interface, Some(&package), &operations)?;
    fs::create_dir_all(output)
        .map_err(|err| format!("创建 SDK 输出目录 {} 失败: {err}", output.display()))?;
    write_json(&output.join("interface.schema.json"), &schema)?;
    fs::write(output.join("lib.rs"), render_sdk(&schema))
        .map_err(|err| format!("写入 Rust SDK 失败: {err}"))?;
    Ok(())
}

pub fn generate_rust_bridge(
    interface_path: &Path,
    adapter_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let interface = KernelInterfaceManifest::load(interface_path)?;
    let operations = OperationAdapter::load(adapter_path)?;
    let schema = build_schema(&interface, None, &operations)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("创建 bridge 输出目录 {} 失败: {err}", parent.display()))?;
    }
    fs::write(output, render_bridge(&schema))
        .map_err(|err| format!("写入 Rust bridge {} 失败: {err}", output.display()))?;
    Ok(())
}

pub fn check_language_package(package_dir: &Path) -> Result<(), String> {
    let package_path = package_dir.join("LanguagePackage.toml");
    let package = LanguagePackage::load(&package_path)?;
    let interface_path = package_dir.join(&package.interface);
    let interface: serde_json::Value = read_json(&interface_path)?;
    let schema = interface
        .get("schema")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "interface schema 缺少 schema".to_string())?;
    if schema != u64::from(INTERFACE_SCHEMA_VERSION) {
        return Err(format!("不支持的 interface schema {schema}"));
    }
    let identity = interface
        .get("interface")
        .ok_or_else(|| "interface schema 缺少 interface 身份".to_string())?;
    if identity.get("profile").and_then(serde_json::Value::as_str) != Some(&package.profile) {
        return Err("package.profile 与 interface schema 不一致".to_string());
    }
    let target = identity
        .get("target")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "interface schema 缺少 target".to_string())?;
    if !package.targets.iter().any(|item| item == target) {
        return Err(format!("package.targets 不包含 interface target {target}"));
    }
    let eki_path = package_dir.join(&package.eki);
    let eki = fs::read(&eki_path)
        .map_err(|err| format!("读取 EKI {} 失败: {err}", eki_path.display()))?;
    elm::parse_eki_image(&eki)
        .map_err(|status| format!("{} 不是有效 EKI: {status:?}", eki_path.display()))?;
    Ok(())
}

fn schema_symbol(symbol: &KernelInterfaceSymbol) -> SchemaSymbol {
    SchemaSymbol {
        api_path: symbol.api_path.clone(),
        item_path: symbol.item_path.clone(),
        link_name: symbol.link_name.clone(),
        contract: symbol.contract.clone(),
        kind: symbol.kind,
        version: symbol.version,
        capabilities: symbol.capabilities,
        rust_abi_sha256: hex_digest(&symbol.rust_abi_hash),
    }
}

fn operation_id(operation: &OperationAdapter) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(OPERATION_ID_DOMAIN);
    for field in [
        operation.api_path.as_str(),
        operation.wire.as_str(),
        operation.request.as_str(),
        operation.response.as_str(),
        operation.ownership.as_str(),
        operation.capability.as_deref().unwrap_or(""),
    ] {
        input.extend_from_slice(&(field.len() as u32).to_le_bytes());
        input.extend_from_slice(field.as_bytes());
    }
    sha256(&input)
}

fn render_sdk(schema: &InterfaceSchema) -> String {
    let mut out = String::new();
    out.push_str("//! 由 cargo elm sdk 生成；不要手工修改。\n#![no_std]\n\n");
    out.push_str("pub type OperationId = [u8; 32];\n\n");
    out.push_str("#[repr(transparent)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct CapabilityHandle(pub u64);\n");
    out.push_str("#[repr(transparent)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct MmioRegion(pub u64);\n");
    out.push_str("#[repr(transparent)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct DmaBuffer(pub u64);\n");
    out.push_str("#[repr(transparent)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct BufferLease(pub u64);\n\n");
    out.push_str(&format!(
        "pub const PACKAGE_ID: &str = {:?};\n",
        schema.package.id
    ));
    out.push_str(&format!(
        "pub const PACKAGE_VERSION: &str = {:?};\n",
        schema.package.version
    ));
    out.push_str(&format!(
        "pub const TARGET: &str = {:?};\n",
        schema.interface.target
    ));
    out.push_str(&format!(
        "pub const PROFILE: &str = {:?};\n",
        schema.interface.profile
    ));
    out.push_str(&format!(
        "pub const INTERFACE_SHA256: &str = {:?};\n\n",
        schema.interface.interface_sha256
    ));
    out.push_str("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct OperationDescriptor {\n    pub id: OperationId,\n    pub api_path: &'static str,\n    pub wire: &'static str,\n    pub request: &'static str,\n    pub response: &'static str,\n    pub ownership: &'static str,\n}\n\n");
    out.push_str("pub static OPERATIONS: &[OperationDescriptor] = &[\n");
    for operation in &schema.operations {
        out.push_str("    OperationDescriptor { id: ");
        render_byte_array(
            &mut out,
            &parse_hex_digest(&operation.id).unwrap_or([0; 32]),
        );
        out.push_str(&format!(
            ", api_path: {:?}, wire: {:?}, request: {:?}, response: {:?}, ownership: {:?} }},\n",
            operation.api_path,
            operation.wire,
            operation.request,
            operation.response,
            operation.ownership
        ));
    }
    out.push_str("];\n\n");
    out.push_str("pub fn operation(api_path: &str) -> Option<&'static OperationDescriptor> {\n    OPERATIONS.iter().find(|operation| operation.api_path == api_path)\n}\n\n");
    out.push_str("pub trait KernelApi {\n    type Error;\n    fn call(&mut self, operation: OperationId, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error>;\n}\n");
    out
}

fn render_bridge(schema: &InterfaceSchema) -> String {
    let mut out = String::new();
    out.push_str("//! 由 cargo elm bridge 生成的语言无关 Rust bridge。\n#![no_std]\n\n");
    out.push_str("pub type OperationId = [u8; 32];\n\n");
    out.push_str("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n#[repr(C)]\npub struct KernelOperation {\n    pub id: OperationId,\n    pub api_path: &'static str,\n    pub link_name: &'static str,\n    pub rust_abi_sha256: &'static str,\n}\n\n");
    out.push_str("pub static KERNEL_OPERATIONS: &[KernelOperation] = &[\n");
    for operation in &schema.operations {
        out.push_str("    KernelOperation { id: ");
        render_byte_array(
            &mut out,
            &parse_hex_digest(&operation.id).unwrap_or([0; 32]),
        );
        out.push_str(&format!(
            ", api_path: {:?}, link_name: {:?}, rust_abi_sha256: {:?} }},\n",
            operation.api_path, operation.symbol.link_name, operation.symbol.rust_abi_sha256
        ));
    }
    out.push_str("];\n\n");
    out.push_str("pub trait KernelBridge {\n    type Error;\n    fn invoke(&mut self, operation: OperationId, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error>;\n}\n\n");
    out.push_str("pub fn operation(api_path: &str) -> Option<&'static KernelOperation> {\n    KERNEL_OPERATIONS.iter().find(|operation| operation.api_path == api_path)\n}\n");
    out
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("创建输出目录 {} 失败: {err}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(value).map_err(|err| format!("编码 schema 失败: {err}"))?;
    fs::write(path, format!("{json}\n"))
        .map_err(|err| format!("写入 {} 失败: {err}", path.display()))
}

fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let input =
        fs::read_to_string(path).map_err(|err| format!("读取 {} 失败: {err}", path.display()))?;
    serde_json::from_str(&input).map_err(|err| format!("解析 {} 失败: {err}", path.display()))
}

fn validate_identifier(value: &str, field: &str, max: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        || matches!(value.as_bytes().first(), Some(b'.' | b'-'))
    {
        return Err(format!("{field} 无效"));
    }
    Ok(())
}

fn validate_version(value: &str, field: &str) -> Result<(), String> {
    let mut parts = value.split('.');
    if parts.clone().count() != 3
        || parts.any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(format!("{field} 必须是 x.y.z 形式"));
    }
    Ok(())
}

fn validate_target(target: &str) -> Result<(), String> {
    if target.is_empty()
        || target.len() > 128
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("无效 target: {target}"));
    }
    Ok(())
}

fn validate_relative_string(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.starts_with('/') || value.contains(['\\', '\0']) {
        return Err(format!("{field} 必须是相对路径"));
    }
    validate_relative_path(Path::new(value), field)
}

fn validate_relative_path(path: &Path, field: &str) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
    {
        return Err(format!("{field} 必须是安全的相对路径"));
    }
    Ok(())
}

fn validate_capability(value: &str) -> Result<(), String> {
    const KNOWN: &[&str] = &[
        "device.discovery",
        "device.mmio.read",
        "device.mmio.write",
        "device.irq",
        "device.dma",
        "network.rx",
        "network.tx",
        "filesystem.block",
    ];
    if !KNOWN.contains(&value) {
        return Err(format!("未知 capability: {value}"));
    }
    Ok(())
}

fn validate_api_path(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("无效 operation.api_path: {value}"));
    }
    Ok(())
}

fn validate_wire(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!("无效 operation.wire: {value}"));
    }
    Ok(())
}

fn validate_type_name(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'<' | b'>' | b',' | b' ')
        })
    {
        return Err(format!("{field} 类型名无效"));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn parse_hex_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("摘要长度无效".to_string());
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(chunk[0])? << 4) | hex_digit(chunk[1])?;
    }
    Ok(output)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("摘要包含非法十六进制字符".to_string()),
    }
}

fn render_byte_array(out: &mut String, bytes: &[u8; 32]) {
    out.push_str("[");
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("0x{byte:02x}"));
    }
    out.push(']');
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::kernel_interface::{
        KERNEL_API_BRIDGE_ABI_V1, KernelInterfaceMixinSite, KernelInterfaceSymbol,
    };

    fn interface() -> KernelInterfaceManifest {
        let mut symbols = vec![KernelInterfaceSymbol {
            kind: 1,
            flags: 0,
            version: 1,
            capabilities: 0,
            retained_argument_mask: 0,
            interface_hash: [0; 32],
            api_path: "general.dev.demo.open".to_string(),
            item_path: "demo::open".to_string(),
            link_name: "_ZN4demo4open".to_string(),
            contract: "general.dev.demo@1".to_string(),
            rust_abi: "fn() -> u64".to_string(),
            rust_abi_hash: [0; 32],
            abi_mode: "exact-rust".to_string(),
            aliases: Vec::new(),
        }];
        let hash = [9; 32];
        symbols[0].interface_hash = hash;
        symbols[0].rust_abi_hash = sha256(symbols[0].rust_abi.as_bytes());
        KernelInterfaceManifest {
            target: "riscv64gc-unknown-none-elf".to_string(),
            profile: "demo".to_string(),
            bridge_abi_version: KERNEL_API_BRIDGE_ABI_V1,
            kernel_hash: [1; 32],
            interface_hash: hash,
            source_hash: [2; 32],
            framework_hash: [3; 32],
            source_file_count: 1,
            metadata: BTreeMap::new(),
            support_library: "support".to_string(),
            import_library: "imports".to_string(),
            symbols,
            mixin_sites: Vec::<KernelInterfaceMixinSite>::new(),
        }
    }

    #[test]
    fn package_rejects_unknown_keys_and_zero_limits() {
        let input = r#"
[package]
schema = 1
id = "demo.driver"
version = "0.1.0"
kind = "driver"
backend = "rust"
targets = ["riscv64gc-unknown-none-elf"]
profile = "demo"
eki = "module.eki"
interface = "interface.schema.json"
[capabilities]
requested = ["device.dma"]
[limits]
max_handles = 1
max_dma_bytes = 1
max_pending_requests = 1
"#;
        assert!(LanguagePackage::parse(input).is_ok());
        assert!(
            LanguagePackage::parse(&input.replace("max_handles = 1", "max_handles = 0")).is_err()
        );
        assert!(LanguagePackage::parse(&format!("{input}\n[unexpected]\nx = 1")).is_err());
    }

    #[test]
    fn adapter_is_sorted_and_validated_against_eki() {
        let input = r#"
[[operation]]
api_path = "general.dev.demo.open"
wire = "device.open"
request = "OpenRequest"
response = "OpenResponse"
ownership = "returns-owned"
capability = "device.discovery"
"#;
        let adapters = OperationAdapter::parse(input).unwrap();
        let schema = build_schema(&interface(), None, &adapters).unwrap();
        assert_eq!(schema.operations[0].id.len(), 64);
        assert!(
            build_schema(
                &interface(),
                None,
                &OperationAdapter::parse(&input.replace("general.dev.demo.open", "missing"))
                    .unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn generated_sources_do_not_emit_untyped_calls() {
        let adapters = OperationAdapter::parse(
            r#"[[operation]]
api_path = "general.dev.demo.open"
wire = "device.open"
request = "OpenRequest"
response = "OpenResponse"
ownership = "none"
"#,
        )
        .unwrap();
        let schema = build_schema(&interface(), None, &adapters).unwrap();
        let bridge = render_bridge(&schema);
        assert!(bridge.contains("trait KernelBridge"));
        assert!(!bridge.contains("extern \"Rust\""));
        assert!(render_sdk(&schema).contains("CapabilityHandle"));
        syn::parse_file(&bridge).expect("generated bridge must parse as Rust");
        syn::parse_file(&render_sdk(&schema)).expect("generated SDK must parse as Rust");
    }
}
