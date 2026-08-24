//! 语言无关 ELM package、IDL、descriptor 与 SDK 生成。
//!
//! 本模块只把经过审核的 Kernel API adapter 转换为固定 wire operation。它不会从 Rust
//! ABI 文本猜测跨语言调用，也不会把函数指针或裸地址写进生成物。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use elm::{ElmEbiArch, ElmEbiImage, sha256};
use kernel_symbols::capability as kernel_capability;
use serde::{Deserialize, Serialize};

use crate::kernel_interface::{KernelInterfaceManifest, KernelInterfaceSymbol};

const PACKAGE_SCHEMA_VERSION: u32 = 2;
const BRIDGE_SCHEMA_VERSION: u32 = 2;
const INTERFACE_SCHEMA_VERSION: u32 = 2;
const DESCRIPTOR_SCHEMA_VERSION: u32 = 1;
const OPERATION_ID_DOMAIN: &[u8] = b"HITOSHIZUKU-ELM-OPERATION-ID-U64-V2\0";
const OPERATION_ID_ALGORITHM: &str = "sha256-trunc64-le-nonzero-v2";
const MAX_WIRE_SIZE: u32 = 192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguagePackage {
    schema: u32,
    id: String,
    version: String,
    kind: String,
    backend: String,
    targets: Vec<String>,
    profile: String,
    eki: PathBuf,
    eki_sha256: String,
    interface: PathBuf,
    interface_sha256: String,
    bridge: PathBuf,
    bridge_sha256: String,
    runtime: RuntimeRequirement,
    artifacts: Vec<Artifact>,
    capabilities: Vec<String>,
    limits: PackageLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRequirement {
    abi: String,
    min_version: u32,
    max_version: u32,
    entrypoint: String,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Artifact {
    path: PathBuf,
    kind: String,
    target: String,
    runtime_abi: String,
    entrypoint: String,
    sha256: String,
    size: u64,
    signature: ArtifactSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ArtifactSignature {
    None,
    Ed25519 {
        public_key: [u8; 32],
        signature: [u8; 64],
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLimits {
    max_handles: u32,
    max_dma_bytes: u64,
    max_pending_requests: u32,
    max_heap_bytes: u64,
    max_stack_bytes: u64,
    max_threads: u32,
    max_metadata_bytes: u64,
    max_artifact_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageDocument {
    package: RawPackage,
    runtime: RuntimeRequirement,
    #[serde(rename = "artifact")]
    artifacts: Vec<RawArtifact>,
    capabilities: RawCapabilities,
    limits: PackageLimits,
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
    eki_sha256: String,
    interface: String,
    interface_sha256: String,
    bridge: String,
    bridge_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    path: String,
    kind: String,
    target: String,
    runtime_abi: String,
    entrypoint: String,
    sha256: String,
    size: u64,
    signature: RawArtifactSignature,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifactSignature {
    algorithm: String,
    public_key: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapabilities {
    #[serde(default)]
    requested: Vec<String>,
}

impl LanguagePackage {
    pub fn load(path: &Path) -> Result<Self, String> {
        let input = fs::read_to_string(path)
            .map_err(|error| format!("读取 {} 失败: {error}", path.display()))?;
        Self::parse(&input)
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let document: PackageDocument = toml::from_str(input)
            .map_err(|error| format!("解析 LanguagePackage.toml 失败: {error}"))?;
        if document.package.schema != PACKAGE_SCHEMA_VERSION {
            return Err(schema_upgrade_error(
                "LanguagePackage",
                document.package.schema,
                PACKAGE_SCHEMA_VERSION,
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
            if targets.contains(&target) {
                return Err(format!("package.targets 重复项: {target}"));
            }
            targets.push(target);
        }
        validate_identifier(&document.package.profile, "package.profile", 64)?;
        for (value, field) in [
            (&document.package.eki, "package.eki"),
            (&document.package.interface, "package.interface"),
            (&document.package.bridge, "package.bridge"),
        ] {
            validate_relative_string(value, field)?;
        }
        for (value, field) in [
            (&document.package.eki_sha256, "package.eki_sha256"),
            (
                &document.package.interface_sha256,
                "package.interface_sha256",
            ),
            (&document.package.bridge_sha256, "package.bridge_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        validate_runtime(&document.runtime)?;
        validate_package_limits(&document.limits)?;

        let mut capabilities = Vec::with_capacity(document.capabilities.requested.len());
        for capability in document.capabilities.requested {
            validate_capability(&capability)?;
            if capabilities.contains(&capability) {
                return Err(format!("capabilities.requested 重复项: {capability}"));
            }
            capabilities.push(capability);
        }
        capabilities.sort();

        if document.artifacts.is_empty() {
            return Err("至少需要一个 [[artifact]]".to_string());
        }
        let mut artifacts = Vec::with_capacity(document.artifacts.len());
        let mut artifact_keys = BTreeSet::new();
        for raw in document.artifacts {
            validate_relative_string(&raw.path, "artifact.path")?;
            if !matches!(raw.kind.as_str(), "eki" | "elf" | "archive" | "blob") {
                return Err(format!("未知 artifact.kind: {}", raw.kind));
            }
            validate_target(&raw.target)?;
            if !targets.contains(&raw.target) {
                return Err(format!(
                    "artifact.target 不在 package.targets 中: {}",
                    raw.target
                ));
            }
            validate_symbol(&raw.entrypoint, "artifact.entrypoint")?;
            validate_runtime_abi(&raw.runtime_abi, "artifact.runtime_abi")?;
            if raw.runtime_abi != document.runtime.abi {
                return Err(format!(
                    "artifact.runtime_abi={} 与 runtime.abi={} 不一致",
                    raw.runtime_abi, document.runtime.abi
                ));
            }
            if raw.entrypoint != document.runtime.entrypoint {
                return Err(format!(
                    "artifact.entrypoint={} 与 runtime.entrypoint={} 不一致",
                    raw.entrypoint, document.runtime.entrypoint
                ));
            }
            validate_sha256(&raw.sha256, "artifact.sha256")?;
            if raw.size == 0 || raw.size > document.limits.max_artifact_bytes {
                return Err(format!("artifact.size 超出 limits: {}", raw.path));
            }
            if !artifact_keys.insert((raw.target.clone(), raw.path.clone())) {
                return Err(format!("重复 artifact: {} {}", raw.target, raw.path));
            }
            artifacts.push(Artifact {
                path: PathBuf::from(raw.path),
                kind: raw.kind,
                target: raw.target,
                runtime_abi: raw.runtime_abi,
                entrypoint: raw.entrypoint,
                sha256: raw.sha256.to_ascii_lowercase(),
                size: raw.size,
                signature: parse_artifact_signature(raw.signature)?,
            });
        }
        for target in &targets {
            if !artifacts.iter().any(|artifact| &artifact.target == target) {
                return Err(format!("target {target} 没有 artifact"));
            }
        }
        let eki_artifact = artifacts
            .iter()
            .find(|artifact| {
                artifact.kind == "eki" && artifact.path == Path::new(&document.package.eki)
            })
            .ok_or_else(|| "package.eki 必须对应一个 kind=eki 的 artifact".to_string())?;
        if eki_artifact.sha256 != document.package.eki_sha256 {
            return Err("package.eki_sha256 必须等于对应 artifact.sha256".to_string());
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
            eki_sha256: document.package.eki_sha256.to_ascii_lowercase(),
            interface: PathBuf::from(document.package.interface),
            interface_sha256: document.package.interface_sha256.to_ascii_lowercase(),
            bridge: PathBuf::from(document.package.bridge),
            bridge_sha256: document.package.bridge_sha256.to_ascii_lowercase(),
            runtime: document.runtime,
            artifacts,
            capabilities,
            limits: document.limits,
        })
    }

    /// 返回目标对应的 artifact。优先选择 EKI，因为 EKI 是 loader 能够校验的
    /// 语言运行时入口；没有 EKI 时保留其它 artifact 作为外部 backend 的身份。
    fn artifact_for_target(&self, target: &str) -> Option<&Artifact> {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.target == target)
            .find(|artifact| artifact.kind == "eki")
            .or_else(|| {
                self.artifacts
                    .iter()
                    .find(|artifact| artifact.target == target)
            })
    }

    /// 计算规范化 package manifest 摘要。
    ///
    /// 摘要输入不依赖 TOML 的空白、表顺序或平台路径分隔符；它绑定 package 身份、
    /// runtime、权限、限制、artifact 摘要和签名元数据，供所有语言生成相同的 V2
    /// `LanguageArtifactIdentity`。
    fn package_digest(&self) -> [u8; 32] {
        let mut canonical = String::new();
        writeln!(canonical, "schema={}", self.schema).unwrap();
        writeln!(canonical, "id={}", self.id).unwrap();
        writeln!(canonical, "version={}", self.version).unwrap();
        writeln!(canonical, "kind={}", self.kind).unwrap();
        writeln!(canonical, "backend={}", self.backend).unwrap();
        let mut targets = self.targets.clone();
        targets.sort();
        for target in &targets {
            writeln!(canonical, "target={target}").unwrap();
        }
        writeln!(canonical, "profile={}", self.profile).unwrap();
        writeln!(canonical, "eki={}", canonical_path(&self.eki)).unwrap();
        writeln!(canonical, "eki_sha256={}", self.eki_sha256).unwrap();
        writeln!(canonical, "interface={}", canonical_path(&self.interface)).unwrap();
        // 不把 interface.schema.json 自身的摘要放进 package digest：schema 会携带
        // package digest，二者互相包含会形成不可构造的循环。profile digest 通过
        // `interface_digest` 单独绑定，schema 文件完整性仍由 package.interface_sha256
        // 校验。
        writeln!(canonical, "bridge={}", canonical_path(&self.bridge)).unwrap();
        writeln!(canonical, "bridge_sha256={}", self.bridge_sha256).unwrap();
        writeln!(canonical, "runtime.abi={}", self.runtime.abi).unwrap();
        writeln!(canonical, "runtime.min={}", self.runtime.min_version).unwrap();
        writeln!(canonical, "runtime.max={}", self.runtime.max_version).unwrap();
        writeln!(canonical, "runtime.entrypoint={}", self.runtime.entrypoint).unwrap();
        let mut features = self.runtime.features.clone();
        features.sort();
        for feature in &features {
            writeln!(canonical, "runtime.feature={feature}").unwrap();
        }
        let mut capabilities = self.capabilities.clone();
        capabilities.sort();
        for capability in &capabilities {
            writeln!(canonical, "capability={capability}").unwrap();
        }
        writeln!(canonical, "limit.max_handles={}", self.limits.max_handles).unwrap();
        writeln!(
            canonical,
            "limit.max_dma_bytes={}",
            self.limits.max_dma_bytes
        )
        .unwrap();
        writeln!(
            canonical,
            "limit.max_pending_requests={}",
            self.limits.max_pending_requests
        )
        .unwrap();
        writeln!(
            canonical,
            "limit.max_heap_bytes={}",
            self.limits.max_heap_bytes
        )
        .unwrap();
        writeln!(
            canonical,
            "limit.max_stack_bytes={}",
            self.limits.max_stack_bytes
        )
        .unwrap();
        writeln!(canonical, "limit.max_threads={}", self.limits.max_threads).unwrap();
        writeln!(
            canonical,
            "limit.max_metadata_bytes={}",
            self.limits.max_metadata_bytes
        )
        .unwrap();
        writeln!(
            canonical,
            "limit.max_artifact_bytes={}",
            self.limits.max_artifact_bytes
        )
        .unwrap();

        let mut artifacts = self.artifacts.iter().collect::<Vec<_>>();
        artifacts.sort_by(|left, right| {
            (&left.target, &left.path, &left.kind).cmp(&(&right.target, &right.path, &right.kind))
        });
        for artifact in artifacts {
            writeln!(
                canonical,
                "artifact={}|{}|{}|{}|{}|{}",
                artifact.target,
                canonical_path(&artifact.path),
                artifact.kind,
                artifact.runtime_abi,
                artifact.entrypoint,
                artifact.sha256
            )
            .unwrap();
            writeln!(canonical, "artifact.size={}", artifact.size).unwrap();
            match &artifact.signature {
                ArtifactSignature::None => canonical.push_str("artifact.signature=none\n"),
                ArtifactSignature::Ed25519 {
                    public_key,
                    signature,
                } => {
                    writeln!(
                        canonical,
                        "artifact.signature=ed25519|{}|{}",
                        hex_digest(public_key),
                        hex_bytes(signature)
                    )
                    .unwrap();
                }
            }
        }
        sha256(canonical.as_bytes())
    }

    fn artifact_identity(
        &self,
        target: &str,
        interface_digest: [u8; 32],
    ) -> Result<(u64, u64, [u8; 32], [u8; 32], [u8; 32]), String> {
        let artifact = self
            .artifact_for_target(target)
            .ok_or_else(|| format!("target {target} 没有可绑定的 artifact"))?;
        let package_id = stable_identity_id(b"package", &self.id);
        let artifact_key = format!(
            "{}|{}|{}",
            artifact.target,
            canonical_path(&artifact.path),
            artifact.kind
        );
        let artifact_id = stable_identity_id(b"artifact", &artifact_key);
        Ok((
            package_id,
            artifact_id,
            self.package_digest(),
            decode_hex::<32>(&artifact.sha256, "artifact.sha256")?,
            interface_digest,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TypeLimits {
    #[serde(default)]
    min_value: Option<i64>,
    #[serde(default)]
    max_value: Option<i64>,
    #[serde(default)]
    max_length: Option<u32>,
    #[serde(default)]
    max_items: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeField {
    name: String,
    #[serde(rename = "type")]
    type_name: String,
    offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnumVariant {
    name: String,
    value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeDef {
    name: String,
    kind: String,
    size: u32,
    align: u32,
    version: u16,
    endian: String,
    ownership: String,
    limits: TypeLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bits: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stride: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    element: Option<String>,
    #[serde(default, rename = "field", skip_serializing_if = "Vec::is_empty")]
    fields: Vec<TypeField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repr: Option<String>,
    #[serde(default, rename = "variant", skip_serializing_if = "Vec::is_empty")]
    variants: Vec<EnumVariant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handle_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationLimits {
    max_request_bytes: u32,
    max_response_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAdapter {
    api_path: String,
    wire: String,
    request: String,
    response: String,
    ownership: String,
    version: u16,
    capability: Option<String>,
    limits: OperationLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeDocument {
    schema: u32,
    endian: String,
    #[serde(rename = "type")]
    types: Vec<TypeDef>,
    #[serde(rename = "operation")]
    operations: Vec<OperationAdapter>,
}

impl BridgeDocument {
    fn load(path: &Path) -> Result<Self, String> {
        let input = fs::read_to_string(path)
            .map_err(|error| format!("读取 {} 失败: {error}", path.display()))?;
        Self::parse(&input)
    }

    fn parse(input: &str) -> Result<Self, String> {
        let mut document: Self = toml::from_str(input)
            .map_err(|error| format!("解析 LanguageBridge.toml 失败: {error}"))?;
        if document.schema != BRIDGE_SCHEMA_VERSION {
            return Err(schema_upgrade_error(
                "LanguageBridge",
                document.schema,
                BRIDGE_SCHEMA_VERSION,
            ));
        }
        if document.endian != "little" {
            return Err("LanguageBridge.endian 当前必须为 little".to_string());
        }
        for ty in &mut document.types {
            ty.variants
                .sort_by(|left, right| (left.value, &left.name).cmp(&(right.value, &right.name)));
        }
        document
            .types
            .sort_by(|left, right| left.name.cmp(&right.name));
        document
            .operations
            .sort_by(|left, right| left.api_path.cmp(&right.api_path));
        validate_type_graph(&document.types)?;
        validate_operations(&document.types, &document.operations)?;
        Ok(document)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceSchema {
    schema: u32,
    operation_id: OperationIdEncoding,
    package: SchemaPackage,
    interface: InterfaceIdentity,
    types: Vec<TypeDef>,
    symbols: Vec<SchemaSymbol>,
    operations: Vec<SchemaOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationIdEncoding {
    algorithm: String,
    domain: String,
    bits: u16,
    endian: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaPackage {
    id: String,
    version: String,
    kind: String,
    backend: String,
    runtime_abi: String,
    runtime_min_version: u32,
    runtime_max_version: u32,
    runtime_entrypoint: String,
    runtime_features: Vec<String>,
    capabilities: Vec<String>,
    limits: PackageLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceIdentity {
    target: String,
    profile: String,
    bridge_abi: u16,
    kernel_sha256: String,
    interface_sha256: String,
    source_sha256: String,
    framework_sha256: String,
    package_id: u64,
    artifact_id: u64,
    package_digest: String,
    artifact_digest: String,
    interface_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaOperation {
    id: u64,
    id_hex: String,
    api_path: String,
    wire: String,
    request: String,
    response: String,
    ownership: String,
    version: u16,
    capability: Option<String>,
    limits: OperationLimits,
    symbol: SchemaOperationSymbol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaOperationSymbol {
    link_name: String,
    contract: String,
    version: u32,
    rust_abi_sha256: String,
}

fn build_schema(
    interface: &KernelInterfaceManifest,
    package: Option<&LanguagePackage>,
    bridge: &BridgeDocument,
) -> Result<InterfaceSchema, String> {
    if let Some(package) = package {
        if !package.targets.contains(&interface.target) {
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
    let (package_id, artifact_id, package_digest, artifact_digest, interface_digest) =
        if let Some(package) = package {
            let (package_id, artifact_id, package_digest, artifact_digest, interface_digest) =
                package.artifact_identity(&interface.target, interface.interface_hash)?;
            (
                package_id,
                artifact_id,
                hex_digest(&package_digest),
                hex_digest(&artifact_digest),
                hex_digest(&interface_digest),
            )
        } else {
            (
                stable_identity_id(b"package", "unbound.bridge"),
                stable_identity_id(b"artifact", &interface.target),
                hex_digest(&sha256(b"HITOSHIZUKU-UNBOUND-PACKAGE-V2")),
                hex_digest(&interface.kernel_hash),
                hex_digest(&interface.interface_hash),
            )
        };
    let mut symbols = interface
        .symbols
        .iter()
        .map(schema_symbol)
        .collect::<Vec<_>>();
    symbols.sort_by(|left, right| left.api_path.cmp(&right.api_path));
    let type_map = type_map(&bridge.types);
    let mut ids = BTreeMap::<u64, String>::new();
    let mut operations = Vec::with_capacity(bridge.operations.len());
    for operation in &bridge.operations {
        let symbol = interface
            .symbols
            .iter()
            .find(|symbol| symbol.api_path == operation.api_path)
            .ok_or_else(|| format!("adapter operation 未导出的 API: {}", operation.api_path))?;
        if let Some(capability) = &operation.capability {
            let bit = capability_bit(capability).ok_or_else(|| {
                format!(
                    "operation {} 使用了无法映射到 kernel symbol 权限位的 capability {}",
                    operation.api_path, capability
                )
            })?;
            if symbol.capabilities & bit != bit {
                return Err(format!(
                    "operation {} 的 capability {} 不在 EKI symbol 权限中",
                    operation.api_path, capability
                ));
            }
            if let Some(package) = package
                && !package.capabilities.contains(capability)
            {
                return Err(format!(
                    "operation {} 使用了 package 未声明的 capability {}",
                    operation.api_path, capability
                ));
            }
        }
        let id = operation_id(operation, &type_map)?;
        if id == 0 {
            return Err(format!("operation id 不能为零: {}", operation.api_path));
        }
        register_operation_id(&mut ids, id, &operation.api_path)?;
        operations.push(SchemaOperation {
            id,
            id_hex: format!("0x{id:016x}"),
            api_path: operation.api_path.clone(),
            wire: operation.wire.clone(),
            request: operation.request.clone(),
            response: operation.response.clone(),
            ownership: operation.ownership.clone(),
            version: operation.version,
            capability: operation.capability.clone(),
            limits: operation.limits.clone(),
            symbol: SchemaOperationSymbol {
                link_name: symbol.link_name.clone(),
                contract: symbol.contract.clone(),
                version: symbol.version,
                rust_abi_sha256: hex_digest(&symbol.rust_abi_hash),
            },
        });
    }
    Ok(InterfaceSchema {
        schema: INTERFACE_SCHEMA_VERSION,
        operation_id: OperationIdEncoding {
            algorithm: OPERATION_ID_ALGORITHM.to_string(),
            domain: String::from_utf8_lossy(&OPERATION_ID_DOMAIN[..OPERATION_ID_DOMAIN.len() - 1])
                .into_owned(),
            bits: 64,
            endian: "little".to_string(),
        },
        package: package.map_or_else(default_schema_package, schema_package),
        interface: InterfaceIdentity {
            target: interface.target.clone(),
            profile: interface.profile.clone(),
            bridge_abi: interface.bridge_abi_version,
            kernel_sha256: hex_digest(&interface.kernel_hash),
            interface_sha256: hex_digest(&interface.interface_hash),
            source_sha256: hex_digest(&interface.source_hash),
            framework_sha256: hex_digest(&interface.framework_hash),
            package_id,
            artifact_id,
            package_digest,
            artifact_digest,
            interface_digest,
        },
        types: bridge.types.clone(),
        symbols,
        operations,
    })
}

pub fn generate_interface_schema(
    interface_path: &Path,
    package_path: Option<&Path>,
    adapter_path: Option<&Path>,
    output: &Path,
) -> Result<(), String> {
    let interface = KernelInterfaceManifest::load(interface_path)?;
    let package = package_path.map(LanguagePackage::load).transpose()?;
    let bridge_path = adapter_path.ok_or_else(|| {
        "schema v2 必须提供 --adapters <LanguageBridge.toml>，类型布局不能再由字符串猜测"
            .to_string()
    })?;
    let bridge = BridgeDocument::load(bridge_path)?;
    let schema = build_schema(&interface, package.as_ref(), &bridge)?;
    write_json(output, &schema)
}

pub fn generate_rust_sdk(
    interface_path: &Path,
    package_path: &Path,
    adapter_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let schema = load_and_build(interface_path, Some(package_path), adapter_path)?;
    write_descriptor_set(output, &schema)?;
    fs::write(output.join("lib.rs"), render_sdk(&schema))
        .map_err(|error| format!("写入 Rust SDK 失败: {error}"))
}

pub fn generate_common_descriptor(
    interface_path: &Path,
    package_path: &Path,
    adapter_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let schema = load_and_build(interface_path, Some(package_path), adapter_path)?;
    write_descriptor_set(output, &schema)
}

pub fn generate_rust_bridge(
    interface_path: &Path,
    adapter_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let schema = load_and_build(interface_path, None, adapter_path)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("创建 bridge 输出目录 {} 失败: {error}", parent.display()))?;
    }
    fs::write(output, render_bridge(&schema))
        .map_err(|error| format!("写入 Rust bridge {} 失败: {error}", output.display()))
}

fn load_and_build(
    interface_path: &Path,
    package_path: Option<&Path>,
    adapter_path: &Path,
) -> Result<InterfaceSchema, String> {
    let interface = KernelInterfaceManifest::load(interface_path)?;
    let package = package_path.map(LanguagePackage::load).transpose()?;
    let bridge = BridgeDocument::load(adapter_path)?;
    build_schema(&interface, package.as_ref(), &bridge)
}

fn write_descriptor_set(output: &Path, schema: &InterfaceSchema) -> Result<(), String> {
    fs::create_dir_all(output).map_err(|error| {
        format!(
            "创建 descriptor 输出目录 {} 失败: {error}",
            output.display()
        )
    })?;
    write_json(&output.join("interface.schema.json"), schema)?;
    write_json(
        &output.join("interface.descriptor.json"),
        &CommonDescriptor::from_schema(schema),
    )?;
    fs::write(output.join("interface.h"), render_c_header(schema))
        .map_err(|error| format!("写入 C header 失败: {error}"))
}

#[derive(Serialize)]
struct CommonDescriptor<'a> {
    schema: u32,
    operation_id: &'a OperationIdEncoding,
    package: &'a SchemaPackage,
    interface: &'a InterfaceIdentity,
    types: &'a [TypeDef],
    operations: Vec<CommonOperation<'a>>,
}

#[derive(Serialize)]
struct CommonOperation<'a> {
    id: u64,
    id_hex: &'a str,
    wire: &'a str,
    request: &'a str,
    response: &'a str,
    ownership: &'a str,
    version: u16,
    capability: Option<&'a str>,
    limits: &'a OperationLimits,
}

impl<'a> CommonDescriptor<'a> {
    fn from_schema(schema: &'a InterfaceSchema) -> Self {
        Self {
            schema: DESCRIPTOR_SCHEMA_VERSION,
            operation_id: &schema.operation_id,
            package: &schema.package,
            interface: &schema.interface,
            types: &schema.types,
            operations: schema
                .operations
                .iter()
                .map(|operation| CommonOperation {
                    id: operation.id,
                    id_hex: &operation.id_hex,
                    wire: &operation.wire,
                    request: &operation.request,
                    response: &operation.response,
                    ownership: &operation.ownership,
                    version: operation.version,
                    capability: operation.capability.as_deref(),
                    limits: &operation.limits,
                })
                .collect(),
        }
    }
}

fn validate_type_graph(types: &[TypeDef]) -> Result<(), String> {
    if types.is_empty() {
        return Err("LanguageBridge.toml 至少需要一个 [[type]]".to_string());
    }
    if types.len() > 256 {
        return Err("type 数量超过 256".to_string());
    }
    let mut names = BTreeSet::new();
    let mut c_names = BTreeSet::new();
    for ty in types {
        validate_type_identifier(&ty.name, "type.name")?;
        if matches!(
            ty.name.as_str(),
            "CodecError" | "OperationId" | "OperationDescriptor" | "KernelApi"
        ) {
            return Err(format!("type.name 与生成 SDK 的保留名称冲突: {}", ty.name));
        }
        if !names.insert(ty.name.clone()) {
            return Err(format!("重复 type.name: {}", ty.name));
        }
        if !c_names.insert(c_identifier(&ty.name)) {
            return Err(format!("type.name 映射为重复 C 标识符: {}", ty.name));
        }
        if ty.size == 0 || ty.size > MAX_WIRE_SIZE {
            return Err(format!(
                "type {} 的 size 必须在 1..={MAX_WIRE_SIZE}",
                ty.name
            ));
        }
        if ty.align == 0 || ty.align > 64 || !ty.align.is_power_of_two() {
            return Err(format!("type {} 的 align 必须是 1..=64 的二次幂", ty.name));
        }
        if ty.version == 0 {
            return Err(format!("type {} 的 version 不能为 0", ty.name));
        }
        if !matches!(
            ty.ownership.as_str(),
            "value" | "owned" | "borrowed" | "lease" | "handle"
        ) {
            return Err(format!(
                "type {} 的 ownership 无效: {}",
                ty.name, ty.ownership
            ));
        }
        match ty.kind.as_str() {
            "integer" => validate_integer_type(ty)?,
            "boolean" => {
                require_layout(ty, 1, 1, "none")?;
                reject_shape(ty, &["limits"])?;
                if ty.limits != TypeLimits::default() {
                    return Err(format!("boolean type {} 不能声明 limits", ty.name));
                }
            }
            "bytes" => {
                if ty.align != 1 || ty.endian != "none" || ty.length != Some(ty.size) {
                    return Err(format!(
                        "bytes type {} 必须 align=1、endian=none、length=size",
                        ty.name
                    ));
                }
                reject_shape(ty, &["length", "limits"])?;
                if let Some(max) = ty.limits.max_length
                    && max != ty.size
                {
                    return Err(format!(
                        "bytes type {} 的 max_length 必须等于固定 wire size {}",
                        ty.name, ty.size
                    ));
                }
                reject_numeric_limits(ty, true)?;
                if ty.limits.max_items.is_some() {
                    return Err(format!("bytes type {} 不能声明 max_items", ty.name));
                }
            }
            "array" => validate_array_type(ty, types)?,
            "struct" => validate_struct_type(ty, types)?,
            "enum" => validate_enum_type(ty, types)?,
            "handle" => {
                require_layout(ty, 8, 8, "little")?;
                reject_shape(ty, &["handle_kind"])?;
                let kind = ty
                    .handle_kind
                    .as_deref()
                    .ok_or_else(|| format!("handle type {} 缺少 handle_kind", ty.name))?;
                if !matches!(
                    kind,
                    "capability" | "mmio" | "dma" | "buffer-lease" | "opaque"
                ) {
                    return Err(format!(
                        "handle type {} 的 handle_kind 无效: {kind}",
                        ty.name
                    ));
                }
                if ty.limits != TypeLimits::default() {
                    return Err(format!("handle type {} 不能声明 limits", ty.name));
                }
            }
            other => return Err(format!("未知 type.kind: {other}")),
        }
    }
    let map = type_map(types);
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for name in map.keys() {
        visit_type(name, &map, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn validate_integer_type(ty: &TypeDef) -> Result<(), String> {
    let bits = ty
        .bits
        .ok_or_else(|| format!("integer type {} 缺少 bits", ty.name))?;
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return Err(format!(
            "integer type {} 的 bits 仅支持 8/16/32/64",
            ty.name
        ));
    }
    if ty.signed.is_none() {
        return Err(format!("integer type {} 缺少 signed", ty.name));
    }
    let endian = if bits == 8 { "none" } else { "little" };
    require_layout(ty, u32::from(bits / 8), u32::from(bits / 8), endian)?;
    reject_shape(ty, &["bits", "signed", "limits"])?;
    reject_collection_limits(ty)?;
    if let (Some(min), Some(max)) = (ty.limits.min_value, ty.limits.max_value)
        && min > max
    {
        return Err(format!(
            "integer type {} 的 min_value 大于 max_value",
            ty.name
        ));
    }
    let signed = ty.signed.unwrap_or(false);
    for value in [ty.limits.min_value, ty.limits.max_value]
        .into_iter()
        .flatten()
    {
        if !integer_value_fits(value, bits, signed) {
            return Err(format!("integer type {} 的 limits 超出表示范围", ty.name));
        }
    }
    Ok(())
}

fn validate_array_type(ty: &TypeDef, types: &[TypeDef]) -> Result<(), String> {
    if ty.endian != "none" {
        return Err(format!("array type {} 必须 endian=none", ty.name));
    }
    reject_shape(ty, &["length", "stride", "element", "limits"])?;
    reject_numeric_limits(ty, true)?;
    if ty.limits.max_length.is_some() {
        return Err(format!("array type {} 不能声明 max_length", ty.name));
    }
    let length = ty
        .length
        .ok_or_else(|| format!("array type {} 缺少 length", ty.name))?;
    let stride = ty
        .stride
        .ok_or_else(|| format!("array type {} 缺少 stride", ty.name))?;
    let element_name = ty
        .element
        .as_deref()
        .ok_or_else(|| format!("array type {} 缺少 element", ty.name))?;
    let element = types
        .iter()
        .find(|candidate| candidate.name == element_name)
        .ok_or_else(|| format!("array type {} 引用了未知 element {element_name}", ty.name))?;
    if length == 0 || stride < element.size || stride % element.align != 0 {
        return Err(format!("array type {} 的 length/stride 无效", ty.name));
    }
    let size = length
        .checked_mul(stride)
        .ok_or_else(|| format!("array type {} 的布局溢出", ty.name))?;
    if size != ty.size || ty.align != element.align {
        return Err(format!(
            "array type {} 的 size/align 与 element 布局不一致",
            ty.name
        ));
    }
    if let Some(max) = ty.limits.max_items
        && (max == 0 || max > length)
    {
        return Err(format!("array type {} 的 max_items 无效", ty.name));
    }
    Ok(())
}

fn validate_struct_type(ty: &TypeDef, types: &[TypeDef]) -> Result<(), String> {
    if ty.endian != "none" || ty.fields.is_empty() {
        return Err(format!(
            "struct type {} 必须 endian=none 且至少有一个 field",
            ty.name
        ));
    }
    reject_shape(ty, &["fields"])?;
    if ty.limits != TypeLimits::default() {
        return Err(format!("struct type {} 不能声明 limits", ty.name));
    }
    let mut names = BTreeSet::new();
    let mut end = 0u32;
    let mut max_align = 1u32;
    for field in &ty.fields {
        validate_type_identifier(&field.name, "field.name")?;
        if !names.insert(field.name.clone()) {
            return Err(format!(
                "struct type {} 有重复 field {}",
                ty.name, field.name
            ));
        }
        let field_ty = types
            .iter()
            .find(|candidate| candidate.name == field.type_name)
            .ok_or_else(|| format!("struct type {} 引用了未知类型 {}", ty.name, field.type_name))?;
        if field.offset < end || field.offset % field_ty.align != 0 {
            return Err(format!(
                "struct type {} 的 field {} 偏移无效",
                ty.name, field.name
            ));
        }
        end = field
            .offset
            .checked_add(field_ty.size)
            .ok_or_else(|| format!("struct type {} 的布局溢出", ty.name))?;
        if end > ty.size {
            return Err(format!(
                "struct type {} 的 field {} 越界",
                ty.name, field.name
            ));
        }
        max_align = max_align.max(field_ty.align);
    }
    if ty.align != max_align || !ty.size.is_multiple_of(ty.align) {
        return Err(format!(
            "struct type {} 的 size/align 不满足固定布局",
            ty.name
        ));
    }
    Ok(())
}

fn validate_enum_type(ty: &TypeDef, types: &[TypeDef]) -> Result<(), String> {
    if ty.variants.is_empty() {
        return Err(format!("enum type {} 至少需要一个 variant", ty.name));
    }
    reject_shape(ty, &["repr", "variants"])?;
    if ty.limits != TypeLimits::default() {
        return Err(format!("enum type {} 不能声明 limits", ty.name));
    }
    let repr_name = ty
        .repr
        .as_deref()
        .ok_or_else(|| format!("enum type {} 缺少 repr", ty.name))?;
    let repr = types
        .iter()
        .find(|candidate| candidate.name == repr_name)
        .ok_or_else(|| format!("enum type {} 引用了未知 repr {repr_name}", ty.name))?;
    if repr.kind != "integer"
        || repr.size != ty.size
        || repr.align != ty.align
        || repr.endian != ty.endian
    {
        return Err(format!("enum type {} 的 repr/size/align 无效", ty.name));
    }
    let bits = repr.bits.unwrap_or(0);
    let signed = repr.signed.unwrap_or(false);
    let mut names = BTreeSet::new();
    let mut constant_names = BTreeSet::new();
    let mut values = BTreeSet::new();
    for variant in &ty.variants {
        validate_type_identifier(&variant.name, "variant.name")?;
        if !names.insert(variant.name.clone()) || !values.insert(variant.value) {
            return Err(format!("enum type {} 的 variant 名称或值重复", ty.name));
        }
        if !constant_names.insert(const_identifier(&variant.name)) {
            return Err(format!(
                "enum type {} 的 variant 映射为重复常量标识符",
                ty.name
            ));
        }
        if !integer_value_fits(variant.value, bits, signed) {
            return Err(format!(
                "enum type {} 的 variant {} 超出 repr",
                ty.name, variant.name
            ));
        }
    }
    Ok(())
}

fn require_layout(ty: &TypeDef, size: u32, align: u32, endian: &str) -> Result<(), String> {
    if ty.size != size || ty.align != align || ty.endian != endian {
        return Err(format!(
            "type {} 的布局必须为 size={size}, align={align}, endian={endian}",
            ty.name
        ));
    }
    Ok(())
}

fn reject_shape(ty: &TypeDef, allowed: &[&str]) -> Result<(), String> {
    let present = [
        ("bits", ty.bits.is_some()),
        ("signed", ty.signed.is_some()),
        ("length", ty.length.is_some()),
        ("stride", ty.stride.is_some()),
        ("element", ty.element.is_some()),
        ("fields", !ty.fields.is_empty()),
        ("repr", ty.repr.is_some()),
        ("variants", !ty.variants.is_empty()),
        ("handle_kind", ty.handle_kind.is_some()),
    ];
    for (name, is_present) in present {
        if is_present && !allowed.contains(&name) {
            return Err(format!("type {} ({}) 不允许字段 {name}", ty.name, ty.kind));
        }
    }
    Ok(())
}

fn reject_numeric_limits(ty: &TypeDef, reject: bool) -> Result<(), String> {
    if reject && (ty.limits.min_value.is_some() || ty.limits.max_value.is_some()) {
        return Err(format!("type {} 不能声明数值 limits", ty.name));
    }
    Ok(())
}

fn reject_collection_limits(ty: &TypeDef) -> Result<(), String> {
    if ty.limits.max_length.is_some() || ty.limits.max_items.is_some() {
        return Err(format!("type {} 不能声明集合 limits", ty.name));
    }
    Ok(())
}

fn integer_value_fits(value: i64, bits: u16, signed: bool) -> bool {
    if signed {
        let shift = u32::from(bits - 1);
        let min = -(1i128 << shift);
        let max = (1i128 << shift) - 1;
        (value as i128) >= min && (value as i128) <= max
    } else {
        value >= 0 && (value as u128) <= ((1u128 << u32::from(bits)) - 1)
    }
}

fn visit_type<'a>(
    name: &'a str,
    types: &BTreeMap<&'a str, &'a TypeDef>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    if visited.contains(name) {
        return Ok(());
    }
    if !visiting.insert(name) {
        return Err(format!("类型图存在递归环: {name}"));
    }
    let ty = types.get(name).ok_or_else(|| format!("未知类型: {name}"))?;
    if let Some(element) = ty.element.as_deref() {
        visit_type(element, types, visiting, visited)?;
    }
    for field in &ty.fields {
        visit_type(&field.type_name, types, visiting, visited)?;
    }
    visiting.remove(name);
    visited.insert(name);
    Ok(())
}

fn validate_operations(types: &[TypeDef], operations: &[OperationAdapter]) -> Result<(), String> {
    if operations.is_empty() {
        return Err("LanguageBridge.toml 至少需要一个 [[operation]]".to_string());
    }
    let map = type_map(types);
    let mut paths = BTreeSet::new();
    let mut wires = BTreeSet::new();
    let mut constant_names = BTreeSet::new();
    for operation in operations {
        validate_api_path(&operation.api_path)?;
        validate_wire(&operation.wire)?;
        if !paths.insert(operation.api_path.clone()) {
            return Err(format!("重复 operation.api_path: {}", operation.api_path));
        }
        if !wires.insert(operation.wire.clone()) {
            return Err(format!("重复 operation.wire: {}", operation.wire));
        }
        if !constant_names.insert(const_identifier(&operation.wire)) {
            return Err(format!(
                "operation.wire 映射为重复常量标识符: {}",
                operation.wire
            ));
        }
        let request = map
            .get(operation.request.as_str())
            .ok_or_else(|| format!("operation {} 的 request 类型不存在", operation.api_path))?;
        let response = map
            .get(operation.response.as_str())
            .ok_or_else(|| format!("operation {} 的 response 类型不存在", operation.api_path))?;
        if operation.version == 0 {
            return Err(format!(
                "operation {} 的 version 不能为 0",
                operation.api_path
            ));
        }
        if !matches!(
            operation.ownership.as_str(),
            "none" | "borrowed" | "returns-owned" | "consumes" | "inout"
        ) {
            return Err(format!("未知 operation.ownership: {}", operation.ownership));
        }
        if let Some(capability) = &operation.capability {
            validate_capability(capability)?;
        }
        if operation.limits.max_request_bytes != request.size
            || operation.limits.max_response_bytes != response.size
        {
            return Err(format!(
                "operation {} 的 byte limits 必须精确等于 request/response 固定布局大小",
                operation.api_path
            ));
        }
    }
    Ok(())
}

fn type_map(types: &[TypeDef]) -> BTreeMap<&str, &TypeDef> {
    types.iter().map(|ty| (ty.name.as_str(), ty)).collect()
}

fn operation_id(
    operation: &OperationAdapter,
    types: &BTreeMap<&str, &TypeDef>,
) -> Result<u64, String> {
    let mut input = Vec::new();
    input.extend_from_slice(OPERATION_ID_DOMAIN);
    append_string(&mut input, &operation.api_path);
    append_string(&mut input, &operation.wire);
    append_string(&mut input, &operation.ownership);
    append_string(&mut input, operation.capability.as_deref().unwrap_or(""));
    input.extend_from_slice(&operation.version.to_le_bytes());
    input.extend_from_slice(&operation.limits.max_request_bytes.to_le_bytes());
    input.extend_from_slice(&operation.limits.max_response_bytes.to_le_bytes());
    append_type_fingerprint(&mut input, &operation.request, types)?;
    append_type_fingerprint(&mut input, &operation.response, types)?;
    let digest = sha256(&input);
    Ok(u64::from_le_bytes(
        digest[..8].try_into().expect("SHA-256 prefix"),
    ))
}

fn register_operation_id(
    ids: &mut BTreeMap<u64, String>,
    id: u64,
    api_path: &str,
) -> Result<(), String> {
    if id == 0 {
        return Err(format!("operation id 不能为零: {api_path}"));
    }
    if let Some(previous) = ids.insert(id, api_path.to_string()) {
        return Err(format!(
            "operation id 冲突 0x{id:016x}: {previous} 与 {api_path}"
        ));
    }
    Ok(())
}

fn append_type_fingerprint(
    output: &mut Vec<u8>,
    name: &str,
    types: &BTreeMap<&str, &TypeDef>,
) -> Result<(), String> {
    let ty = types.get(name).ok_or_else(|| format!("未知类型: {name}"))?;
    append_string(output, &ty.name);
    append_string(output, &ty.kind);
    output.extend_from_slice(&ty.size.to_le_bytes());
    output.extend_from_slice(&ty.align.to_le_bytes());
    output.extend_from_slice(&ty.version.to_le_bytes());
    append_string(output, &ty.endian);
    append_string(output, &ty.ownership);
    append_option_i64(output, ty.limits.min_value);
    append_option_i64(output, ty.limits.max_value);
    append_option_u32(output, ty.limits.max_length);
    append_option_u32(output, ty.limits.max_items);
    append_option_u16(output, ty.bits);
    output.push(ty.signed.map_or(0, |value| if value { 2 } else { 1 }));
    append_option_u32(output, ty.length);
    append_option_u32(output, ty.stride);
    append_string(output, ty.handle_kind.as_deref().unwrap_or(""));
    if let Some(element) = ty.element.as_deref() {
        output.push(1);
        append_type_fingerprint(output, element, types)?;
    } else {
        output.push(0);
    }
    output.extend_from_slice(&(ty.fields.len() as u32).to_le_bytes());
    for field in &ty.fields {
        append_string(output, &field.name);
        output.extend_from_slice(&field.offset.to_le_bytes());
        append_type_fingerprint(output, &field.type_name, types)?;
    }
    if let Some(repr) = ty.repr.as_deref() {
        output.push(1);
        append_type_fingerprint(output, repr, types)?;
    } else {
        output.push(0);
    }
    output.extend_from_slice(&(ty.variants.len() as u32).to_le_bytes());
    for variant in &ty.variants {
        append_string(output, &variant.name);
        output.extend_from_slice(&variant.value.to_le_bytes());
    }
    Ok(())
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_le_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn append_option_u16(output: &mut Vec<u8>, value: Option<u16>) {
    output.push(u8::from(value.is_some()));
    output.extend_from_slice(&value.unwrap_or_default().to_le_bytes());
}

fn append_option_u32(output: &mut Vec<u8>, value: Option<u32>) {
    output.push(u8::from(value.is_some()));
    output.extend_from_slice(&value.unwrap_or_default().to_le_bytes());
}

fn append_option_i64(output: &mut Vec<u8>, value: Option<i64>) {
    output.push(u8::from(value.is_some()));
    output.extend_from_slice(&value.unwrap_or_default().to_le_bytes());
}

fn render_sdk(schema: &InterfaceSchema) -> String {
    let mut out = String::new();
    out.push_str("//! 由 `cargo elm sdk` 生成；固定布局 wire codec，不承诺目标语言内存布局。\n#![no_std]\n\n");
    out.push_str("pub type OperationId = u64;\n\n");
    out.push_str("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum CodecError { Length, InvalidValue, NonZeroPadding }\n\n");
    writeln!(out, "pub const PACKAGE_ID: &str = {:?};", schema.package.id).unwrap();
    writeln!(
        out,
        "pub const PACKAGE_VERSION: &str = {:?};",
        schema.package.version
    )
    .unwrap();
    writeln!(
        out,
        "pub const TARGET: &str = {:?};",
        schema.interface.target
    )
    .unwrap();
    writeln!(
        out,
        "pub const PROFILE: &str = {:?};",
        schema.interface.profile
    )
    .unwrap();
    writeln!(
        out,
        "pub const INTERFACE_SHA256: &str = {:?};\n",
        schema.interface.interface_sha256
    )
    .unwrap();
    let map = type_map(&schema.types);
    for ty in &schema.types {
        writeln!(out, "#[derive(Clone, Copy, Debug, Eq, PartialEq)]").unwrap();
        writeln!(out, "pub struct {} {{ bytes: [u8; {}] }}", ty.name, ty.size).unwrap();
        writeln!(out, "impl {} {{", ty.name).unwrap();
        writeln!(out, "    pub const SIZE: usize = {};", ty.size).unwrap();
        writeln!(
            out,
            "    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {{"
        )
        .unwrap();
        writeln!(
            out,
            "        if input.len() != Self::SIZE {{ return Err(CodecError::Length); }}"
        )
        .unwrap();
        writeln!(
            out,
            "        let mut bytes = [0u8; {}]; bytes.copy_from_slice(input);",
            ty.size
        )
        .unwrap();
        writeln!(
            out,
            "        validate_{}(&bytes)?; Ok(Self {{ bytes }})",
            ty.name
        )
        .unwrap();
        writeln!(out, "    }}\n    pub fn encode(self) -> [u8; {}] {{ self.bytes }}\n    pub fn as_bytes(&self) -> &[u8; {}] {{ &self.bytes }}", ty.size, ty.size).unwrap();
        if ty.kind == "handle" {
            out.push_str("    pub fn from_raw(raw: u64) -> Self { Self { bytes: raw.to_le_bytes() } }\n    pub fn raw(self) -> u64 { u64::from_le_bytes(self.bytes) }\n");
        }
        out.push_str("}\n");
        render_type_validator(&mut out, ty, &map);
        out.push('\n');
    }
    out.push_str("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct OperationDescriptor {\n    pub id: OperationId,\n    pub wire: &'static str,\n    pub request_size: usize,\n    pub response_size: usize,\n    pub version: u16,\n}\n\n");
    for operation in &schema.operations {
        writeln!(
            out,
            "pub const OP_{}: OperationId = 0x{:016x};",
            const_identifier(&operation.wire),
            operation.id
        )
        .unwrap();
    }
    out.push_str("\npub static OPERATIONS: &[OperationDescriptor] = &[\n");
    for operation in &schema.operations {
        writeln!(
            out,
            "    OperationDescriptor {{ id: OP_{}, wire: {:?}, request_size: {}, response_size: {}, version: {} }},",
            const_identifier(&operation.wire),
            operation.wire,
            operation.limits.max_request_bytes,
            operation.limits.max_response_bytes,
            operation.version
        )
        .unwrap();
    }
    out.push_str("];\n\npub trait KernelApi {\n    type Error;\n    fn call(&mut self, operation: OperationId, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error>;\n}\n");
    out
}

fn render_type_validator(out: &mut String, ty: &TypeDef, types: &BTreeMap<&str, &TypeDef>) {
    writeln!(
        out,
        "fn validate_{}(bytes: &[u8; {}]) -> Result<(), CodecError> {{",
        ty.name, ty.size
    )
    .unwrap();
    match ty.kind.as_str() {
        "boolean" => {
            out.push_str("    if bytes[0] > 1 { return Err(CodecError::InvalidValue); }\n")
        }
        "integer" => {
            if ty.limits.min_value.is_some() || ty.limits.max_value.is_some() {
                let bits = ty.bits.unwrap_or(8);
                let rust_ty = if ty.signed.unwrap_or(false) {
                    format!("i{bits}")
                } else {
                    format!("u{bits}")
                };
                if bits == 8 {
                    writeln!(out, "    let value = bytes[0] as {rust_ty};").unwrap();
                } else {
                    writeln!(out, "    let value = {rust_ty}::from_le_bytes(*bytes);").unwrap();
                }
                if let Some(min) = ty.limits.min_value {
                    writeln!(out, "    if (value as i128) < {min}i128 {{ return Err(CodecError::InvalidValue); }}").unwrap();
                }
                if let Some(max) = ty.limits.max_value {
                    writeln!(out, "    if (value as i128) > {max}i128 {{ return Err(CodecError::InvalidValue); }}").unwrap();
                }
            }
        }
        "enum" => {
            let repr = types[ty.repr.as_deref().unwrap()];
            let bits = repr.bits.unwrap();
            let rust_ty = if repr.signed.unwrap() {
                format!("i{bits}")
            } else {
                format!("u{bits}")
            };
            if bits == 8 {
                writeln!(out, "    let value = bytes[0] as {rust_ty};").unwrap();
            } else {
                writeln!(out, "    let value = {rust_ty}::from_le_bytes(*bytes);").unwrap();
            }
            out.push_str("    if !matches!(value as i128, ");
            for (index, variant) in ty.variants.iter().enumerate() {
                if index != 0 {
                    out.push_str(" | ");
                }
                write!(out, "{}", variant.value).unwrap();
            }
            out.push_str(") { return Err(CodecError::InvalidValue); }\n");
        }
        "array" => {
            let element = types[ty.element.as_deref().unwrap()];
            let stride = ty.stride.unwrap();
            for index in 0..ty.length.unwrap() {
                let start = index * stride;
                let end = start + element.size;
                writeln!(
                    out,
                    "    {}::decode(&bytes[{start}..{end}])?;",
                    element.name
                )
                .unwrap();
                if end < start + stride {
                    writeln!(out, "    if bytes[{end}..{}].iter().any(|byte| *byte != 0) {{ return Err(CodecError::NonZeroPadding); }}", start + stride).unwrap();
                }
            }
        }
        "struct" => {
            let mut end = 0u32;
            for field in &ty.fields {
                if end < field.offset {
                    writeln!(out, "    if bytes[{end}..{}].iter().any(|byte| *byte != 0) {{ return Err(CodecError::NonZeroPadding); }}", field.offset).unwrap();
                }
                let field_ty = types[field.type_name.as_str()];
                let field_end = field.offset + field_ty.size;
                writeln!(
                    out,
                    "    {}::decode(&bytes[{}..{field_end}])?;",
                    field_ty.name, field.offset
                )
                .unwrap();
                end = field_end;
            }
            if end < ty.size {
                writeln!(out, "    if bytes[{end}..{}].iter().any(|byte| *byte != 0) {{ return Err(CodecError::NonZeroPadding); }}", ty.size).unwrap();
            }
        }
        _ => {}
    }
    out.push_str("    Ok(())\n}\n");
}

fn render_c_header(schema: &InterfaceSchema) -> String {
    let mut out = String::new();
    out.push_str("/* 由 cargo elm descriptor/sdk 生成；wire 类型使用字节数组，避免依赖 C ABI 布局。 */\n#ifndef HITOSHIZUKU_ELM_INTERFACE_H\n#define HITOSHIZUKU_ELM_INTERFACE_H\n#include <stddef.h>\n#include <stdint.h>\n\ntypedef uint64_t hitoshizuku_elm_operation_id;\n");
    for ty in &schema.types {
        writeln!(
            out,
            "typedef struct {{ uint8_t bytes[{}]; }} hitoshizuku_elm_{};",
            ty.size,
            c_identifier(&ty.name)
        )
        .unwrap();
        writeln!(
            out,
            "#define HITOSHIZUKU_ELM_SIZE_{} UINT32_C({})",
            const_identifier(&ty.name),
            ty.size
        )
        .unwrap();
        if ty.kind == "enum" {
            for variant in &ty.variants {
                writeln!(
                    out,
                    "#define HITOSHIZUKU_ELM_{}_{} INT64_C({})",
                    const_identifier(&ty.name),
                    const_identifier(&variant.name),
                    variant.value
                )
                .unwrap();
            }
        }
    }
    out.push('\n');
    for operation in &schema.operations {
        writeln!(
            out,
            "#define HITOSHIZUKU_ELM_OP_{} UINT64_C(0x{:016x})",
            const_identifier(&operation.wire),
            operation.id
        )
        .unwrap();
    }
    out.push_str("\n#endif\n");
    out
}

fn render_bridge(schema: &InterfaceSchema) -> String {
    let mut out = String::new();
    out.push_str("//! 由 `cargo elm bridge` 生成的语言无关 Rust bridge。\n#![no_std]\n\npub type OperationId = u64;\n\n");
    out.push_str("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct KernelOperation {\n    pub id: OperationId,\n    pub api_path: &'static str,\n    pub link_name: &'static str,\n    pub request_size: usize,\n    pub response_size: usize,\n}\n\n");
    out.push_str("pub static KERNEL_OPERATIONS: &[KernelOperation] = &[\n");
    for operation in &schema.operations {
        writeln!(out, "    KernelOperation {{ id: 0x{:016x}, api_path: {:?}, link_name: {:?}, request_size: {}, response_size: {} }},", operation.id, operation.api_path, operation.symbol.link_name, operation.limits.max_request_bytes, operation.limits.max_response_bytes).unwrap();
    }
    out.push_str("];\n\npub trait KernelBridge {\n    type Error;\n    fn invoke(&mut self, operation: OperationId, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error>;\n}\n");
    out
}

pub fn check_language_package(package_dir: &Path) -> Result<(), String> {
    check_language_package_with_trust(package_dir, None)
}

/// 校验语言包；`trusted_key` 用于把清单中的 Ed25519 公钥锚定到外部信任根。
///
/// 未提供信任根时仍执行摘要、格式和自签名校验，但不能证明发布者身份；发布流程应始终
/// 传入发行版的受信公钥。
pub fn check_language_package_with_trust(
    package_dir: &Path,
    trusted_key: Option<&str>,
) -> Result<(), String> {
    let root = package_dir
        .canonicalize()
        .map_err(|error| format!("定位 package 目录 {} 失败: {error}", package_dir.display()))?;
    if !root.is_dir() {
        return Err(format!("{} 不是目录", package_dir.display()));
    }
    let package_path = root.join("LanguagePackage.toml");
    let package = LanguagePackage::load(&package_path)?;

    let interface_bytes = read_package_file(&root, &package.interface, "package.interface")?;
    verify_digest(
        &interface_bytes,
        &package.interface_sha256,
        "package.interface",
    )?;
    if interface_bytes.len() as u64 > package.limits.max_metadata_bytes {
        return Err("interface schema 超出 limits.max_metadata_bytes".to_string());
    }
    let schema: InterfaceSchema = serde_json::from_slice(&interface_bytes)
        .map_err(|error| format!("解析 {} 失败: {error}", package.interface.display()))?;
    validate_interface_schema(&schema)?;

    let bridge_bytes = read_package_file(&root, &package.bridge, "package.bridge")?;
    verify_digest(&bridge_bytes, &package.bridge_sha256, "package.bridge")?;
    if bridge_bytes.len() as u64 > package.limits.max_metadata_bytes {
        return Err("LanguageBridge.toml 超出 limits.max_metadata_bytes".to_string());
    }
    let bridge_text = std::str::from_utf8(&bridge_bytes)
        .map_err(|_| "LanguageBridge.toml 不是 UTF-8".to_string())?;
    let bridge = BridgeDocument::parse(bridge_text)?;
    compare_bridge_schema(&bridge, &schema)?;
    if schema.package != schema_package(&package) {
        return Err(
            "interface schema 的 package/runtime/capability/limits 与 LanguagePackage.toml 不一致"
                .to_string(),
        );
    }
    if package.profile != schema.interface.profile
        || !package.targets.contains(&schema.interface.target)
    {
        return Err(
            "interface schema 的 target/profile 与 LanguagePackage.toml 不一致".to_string(),
        );
    }
    let interface_digest = decode_hex::<32>(
        &schema.interface.interface_sha256,
        "interface.interface_sha256",
    )?;
    let (package_id, artifact_id, package_digest, artifact_digest, interface_digest) =
        package.artifact_identity(&schema.interface.target, interface_digest)?;
    if schema.interface.package_id != package_id
        || schema.interface.artifact_id != artifact_id
        || schema.interface.package_digest != hex_digest(&package_digest)
        || schema.interface.artifact_digest != hex_digest(&artifact_digest)
        || schema.interface.interface_digest != hex_digest(&interface_digest)
    {
        return Err(
            "interface schema 的 package/artifact identity 与 LanguagePackage.toml 不一致"
                .to_string(),
        );
    }

    let eki_bytes = read_package_file(&root, &package.eki, "package.eki")?;
    verify_digest(&eki_bytes, &package.eki_sha256, "package.eki")?;
    let package_eki = elm::parse_eki_image(&eki_bytes)
        .map_err(|status| format!("{} 不是有效 EKI: {status:?}", package.eki.display()))?;
    let eki_artifact = package
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "eki" && artifact.path == package.eki)
        .expect("parser checked EKI artifact");
    if eki_artifact.target != schema.interface.target {
        return Err(format!(
            "package.eki 的 target {} 与 interface schema target {} 不一致",
            eki_artifact.target, schema.interface.target
        ));
    }
    validate_eki_binding(
        &package_eki,
        &schema,
        &schema.interface.target,
        "package.eki",
    )?;
    let trusted_key = trusted_key
        .map(|value| decode_hex::<32>(value, "--trusted-key"))
        .transpose()?;

    for artifact in &package.artifacts {
        let bytes = read_package_file(&root, &artifact.path, "artifact.path")?;
        if bytes.len() as u64 != artifact.size {
            return Err(format!(
                "artifact {} 的实际大小与清单不一致",
                artifact.path.display()
            ));
        }
        if bytes.len() as u64 > package.limits.max_artifact_bytes {
            return Err(format!(
                "artifact {} 超出 max_artifact_bytes",
                artifact.path.display()
            ));
        }
        verify_digest(
            &bytes,
            &artifact.sha256,
            &format!("artifact {}", artifact.path.display()),
        )?;
        verify_artifact_signature(artifact, &bytes, trusted_key.as_ref())?;
        if artifact.kind == "eki" {
            let image = elm::parse_eki_image(&bytes).map_err(|status| {
                format!(
                    "artifact {} 不是有效 EKI: {status:?}",
                    artifact.path.display()
                )
            })?;
            validate_eki_binding(&image, &schema, &artifact.target, "artifact.path")?;
        }
        if artifact.runtime_abi != package.runtime.abi
            || artifact.entrypoint != package.runtime.entrypoint
        {
            return Err(format!(
                "artifact {} 的 runtime ABI/entrypoint 不一致",
                artifact.path.display()
            ));
        }
    }
    if eki_artifact.sha256 != package.eki_sha256 {
        return Err("package.eki_sha256 与对应 artifact.sha256 不一致".to_string());
    }
    Ok(())
}

fn validate_eki_binding(
    image: &ElmEbiImage,
    schema: &InterfaceSchema,
    target: &str,
    label: &str,
) -> Result<(), String> {
    let expected_profile = decode_hex::<32>(
        &schema.interface.interface_sha256,
        "interface.interface_sha256",
    )?;
    let fingerprint = image
        .abi_fingerprint
        .as_ref()
        .ok_or_else(|| format!("{label} 缺少 kernel API ABI fingerprint"))?;
    if fingerprint.kernel_api_profile_hash != expected_profile {
        return Err(format!(
            "{label} 的 kernel API profile hash 与 schema 不一致"
        ));
    }
    if fingerprint.kernel_api_bridge_abi_version != schema.interface.bridge_abi {
        return Err(format!("{label} 的 bridge ABI 与 schema 不一致"));
    }
    let expected_arch = target_arch(target).ok_or_else(|| {
        format!("{label} 的 target 不属于当前 ELM 支持的 RISC-V/LoongArch 架构: {target}")
    })?;
    if image.unit.target.arch != expected_arch {
        return Err(format!(
            "{label} 的 EKI 架构 {:?} 与 target {target} 不一致",
            image.unit.target.arch
        ));
    }
    Ok(())
}

fn target_arch(target: &str) -> Option<ElmEbiArch> {
    if target.starts_with("riscv64") {
        Some(ElmEbiArch::Riscv64)
    } else if target.starts_with("loongarch64") {
        Some(ElmEbiArch::LoongArch64)
    } else {
        None
    }
}

fn capability_bit(name: &str) -> Option<u64> {
    Some(match name {
        "core.safe" => kernel_capability::CORE_SAFE,
        "allocator.memory" => kernel_capability::ALLOCATOR_MEMORY,
        "allocator.diagnostic" => kernel_capability::ALLOCATOR_DIAGNOSTIC,
        "allocator.physical" => kernel_capability::ALLOCATOR_PHYSICAL,
        "allocator.managed" => kernel_capability::ALLOCATOR_MANAGED,
        "allocator.admin" => kernel_capability::ALLOCATOR_ADMIN,
        "vfs.query" => kernel_capability::VFS_QUERY,
        "vfs.io" => kernel_capability::VFS_IO,
        "vfs.admin" => kernel_capability::VFS_ADMIN,
        "vfs.driver" => kernel_capability::VFS_DRIVER,
        "sched.query" => kernel_capability::SCHED_QUERY,
        "sched.task" => kernel_capability::SCHED_TASK,
        "sched.admin" => kernel_capability::SCHED_ADMIN,
        "sched.hook" => kernel_capability::SCHED_HOOK,
        "mm.query" => kernel_capability::MM_QUERY,
        "mm.memory" => kernel_capability::MM_MEMORY,
        "mm.admin" => kernel_capability::MM_ADMIN,
        "device.discovery" => kernel_capability::DEVICE_DISCOVERY,
        "device.driver" => kernel_capability::DEVICE_DRIVER,
        "device.resource" => kernel_capability::DEVICE_RESOURCE,
        "device.dma" => kernel_capability::DEVICE_DMA,
        "device.interrupt" => kernel_capability::DEVICE_INTERRUPT,
        "device.bus" => kernel_capability::DEVICE_BUS,
        "device.admin" => kernel_capability::DEVICE_ADMIN,
        "image.parse" => kernel_capability::IMAGE_PARSE,
        "firmware.query" => kernel_capability::FIRMWARE_QUERY,
        "firmware.admin" => kernel_capability::FIRMWARE_ADMIN,
        "filesystem.driver" => kernel_capability::FILESYSTEM_DRIVER,
        "ipc" => kernel_capability::IPC,
        "hal.query" => kernel_capability::HAL_QUERY,
        "hal.control" => kernel_capability::HAL_CONTROL,
        "network.stack" => kernel_capability::NETWORK_STACK,
        _ => return None,
    })
}

fn validate_interface_schema(schema: &InterfaceSchema) -> Result<(), String> {
    if schema.schema != INTERFACE_SCHEMA_VERSION {
        return Err(schema_upgrade_error(
            "interface schema",
            schema.schema,
            INTERFACE_SCHEMA_VERSION,
        ));
    }
    if schema.operation_id.algorithm != OPERATION_ID_ALGORITHM
        || schema.operation_id.domain
            != String::from_utf8_lossy(&OPERATION_ID_DOMAIN[..OPERATION_ID_DOMAIN.len() - 1])
        || schema.operation_id.bits != 64
        || schema.operation_id.endian != "little"
    {
        return Err("interface schema 的 operation_id 编码不受支持".to_string());
    }
    validate_schema_package(&schema.package)?;
    validate_target(&schema.interface.target)?;
    validate_identifier(&schema.interface.profile, "interface.profile", 64)?;
    if schema.interface.bridge_abi == 0 {
        return Err("interface.bridge_abi 不能为零".to_string());
    }
    for (value, field) in [
        (&schema.interface.kernel_sha256, "interface.kernel_sha256"),
        (
            &schema.interface.interface_sha256,
            "interface.interface_sha256",
        ),
        (&schema.interface.source_sha256, "interface.source_sha256"),
        (
            &schema.interface.framework_sha256,
            "interface.framework_sha256",
        ),
    ] {
        validate_sha256(value, field)?;
    }
    if schema.interface.package_id == 0 || schema.interface.artifact_id == 0 {
        return Err("interface identity 的 package_id/artifact_id 不能为零".to_string());
    }
    for (value, field) in [
        (&schema.interface.package_digest, "interface.package_digest"),
        (
            &schema.interface.artifact_digest,
            "interface.artifact_digest",
        ),
        (
            &schema.interface.interface_digest,
            "interface.interface_digest",
        ),
    ] {
        validate_sha256(value, field)?;
    }
    validate_type_graph(&schema.types)?;
    if !schema
        .types
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name)
    {
        return Err("interface schema 的 types 必须按 name 严格排序".to_string());
    }
    let adapters = schema
        .operations
        .iter()
        .map(|operation| OperationAdapter {
            api_path: operation.api_path.clone(),
            wire: operation.wire.clone(),
            request: operation.request.clone(),
            response: operation.response.clone(),
            ownership: operation.ownership.clone(),
            version: operation.version,
            capability: operation.capability.clone(),
            limits: operation.limits.clone(),
        })
        .collect::<Vec<_>>();
    validate_operations(&schema.types, &adapters)?;
    if !schema
        .operations
        .windows(2)
        .all(|pair| pair[0].api_path < pair[1].api_path)
    {
        return Err("interface schema 的 operations 必须按 api_path 严格排序".to_string());
    }
    if schema.symbols.len() > 4096
        || !schema
            .symbols
            .windows(2)
            .all(|pair| pair[0].api_path < pair[1].api_path)
    {
        return Err(
            "interface schema 的 symbols 必须唯一、按 api_path 排序且不超过 4096 项".to_string(),
        );
    }
    for symbol in &schema.symbols {
        validate_api_path(&symbol.api_path)?;
        if symbol.item_path.is_empty() || symbol.item_path.len() > 512 {
            return Err(format!("symbol {} 的 item_path 无效", symbol.api_path));
        }
        validate_link_name(&symbol.link_name, "symbol.link_name")?;
        if symbol.contract.is_empty() || symbol.contract.len() > 256 {
            return Err(format!("symbol {} 的 contract 无效", symbol.api_path));
        }
        if symbol.kind == 0 || symbol.version == 0 {
            return Err(format!("symbol {} 的 kind/version 无效", symbol.api_path));
        }
        validate_sha256(&symbol.rust_abi_sha256, "symbol.rust_abi_sha256")?;
    }
    let map = type_map(&schema.types);
    let mut ids = BTreeSet::new();
    let symbol_paths = schema
        .symbols
        .iter()
        .map(|symbol| symbol.api_path.as_str())
        .collect::<BTreeSet<_>>();
    if symbol_paths.len() != schema.symbols.len() {
        return Err("interface schema 有重复 symbol.api_path".to_string());
    }
    for (operation, adapter) in schema.operations.iter().zip(adapters.iter()) {
        let expected = operation_id(adapter, &map)?;
        if expected == 0
            || operation.id != expected
            || operation.id_hex != format!("0x{expected:016x}")
        {
            return Err(format!(
                "operation {} 的 ID/id_hex 无效",
                operation.api_path
            ));
        }
        if !ids.insert(expected) {
            return Err(format!("operation ID 冲突: 0x{expected:016x}"));
        }
        let symbol = schema
            .symbols
            .iter()
            .find(|symbol| symbol.api_path == operation.api_path)
            .ok_or_else(|| format!("operation {} 没有对应 symbol", operation.api_path))?;
        if let Some(capability) = &operation.capability {
            let bit = capability_bit(capability).ok_or_else(|| {
                format!(
                    "operation {} 的 capability 无法映射到 kernel symbol 权限位: {}",
                    operation.api_path, capability
                )
            })?;
            if symbol.capabilities & bit != bit {
                return Err(format!(
                    "operation {} 的 capability {} 不在 EKI symbol 权限中",
                    operation.api_path, capability
                ));
            }
        }
        if symbol.link_name != operation.symbol.link_name
            || symbol.contract != operation.symbol.contract
            || symbol.version != operation.symbol.version
            || symbol.rust_abi_sha256 != operation.symbol.rust_abi_sha256
        {
            return Err(format!(
                "operation {} 的 symbol 快照不一致",
                operation.api_path
            ));
        }
    }
    validate_generated_namespaces(schema)?;
    Ok(())
}

fn validate_generated_namespaces(schema: &InterfaceSchema) -> Result<(), String> {
    let mut rust_values = BTreeSet::new();
    let mut c_macros = BTreeSet::new();
    for ty in &schema.types {
        let rust_validator = format!("validate_{}", ty.name);
        if !rust_values.insert(rust_validator) {
            return Err(format!("生成 Rust validator 名称冲突: {}", ty.name));
        }
        let c_type = format!("hitoshizuku_elm_{}", c_identifier(&ty.name));
        if !c_macros.insert(c_type) {
            return Err(format!("生成 C 类型名称冲突: {}", ty.name));
        }
        if !c_macros.insert(format!(
            "HITOSHIZUKU_ELM_SIZE_{}",
            const_identifier(&ty.name)
        )) {
            return Err(format!("生成 C size 宏名称冲突: {}", ty.name));
        }
        if ty.kind == "enum" {
            for variant in &ty.variants {
                if !c_macros.insert(format!(
                    "HITOSHIZUKU_ELM_{}_{}",
                    const_identifier(&ty.name),
                    const_identifier(&variant.name)
                )) {
                    return Err(format!(
                        "生成 C enum 宏名称冲突: {}::{}",
                        ty.name, variant.name
                    ));
                }
            }
        }
    }
    for operation in &schema.operations {
        let rust_constant = format!("OP_{}", const_identifier(&operation.wire));
        if !rust_values.insert(rust_constant.clone()) {
            return Err(format!("生成 Rust operation 名称冲突: {rust_constant}"));
        }
        let c_macro = format!("HITOSHIZUKU_ELM_OP_{}", const_identifier(&operation.wire));
        if !c_macros.insert(c_macro.clone()) {
            return Err(format!("生成 C operation 宏名称冲突: {c_macro}"));
        }
    }
    Ok(())
}

fn validate_schema_package(package: &SchemaPackage) -> Result<(), String> {
    validate_identifier(&package.id, "schema.package.id", 128)?;
    validate_version(&package.version, "schema.package.version")?;
    if !matches!(
        package.kind.as_str(),
        "driver" | "service" | "filesystem" | "network" | "extension" | "other"
    ) {
        return Err(format!("schema.package.kind 无效: {}", package.kind));
    }
    validate_identifier(&package.backend, "schema.package.backend", 64)?;
    validate_runtime(&RuntimeRequirement {
        abi: package.runtime_abi.clone(),
        min_version: package.runtime_min_version,
        max_version: package.runtime_max_version,
        entrypoint: package.runtime_entrypoint.clone(),
        features: package.runtime_features.clone(),
    })?;
    if !package
        .runtime_features
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err("schema.package.runtime_features 必须唯一且排序".to_string());
    }
    if !package
        .capabilities
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err("schema.package.capabilities 必须唯一且排序".to_string());
    }
    for capability in &package.capabilities {
        validate_capability(capability)?;
    }
    validate_package_limits(&package.limits)
}

fn compare_bridge_schema(bridge: &BridgeDocument, schema: &InterfaceSchema) -> Result<(), String> {
    if bridge.types != schema.types {
        return Err("LanguageBridge.toml 的类型图与 interface schema 不一致".to_string());
    }
    if bridge.operations.len() != schema.operations.len() {
        return Err("LanguageBridge.toml 的 operation 数量与 interface schema 不一致".to_string());
    }
    let map = type_map(&bridge.types);
    for (adapter, operation) in bridge.operations.iter().zip(schema.operations.iter()) {
        if adapter.api_path != operation.api_path
            || adapter.wire != operation.wire
            || adapter.request != operation.request
            || adapter.response != operation.response
            || adapter.ownership != operation.ownership
            || adapter.version != operation.version
            || adapter.capability != operation.capability
            || adapter.limits != operation.limits
            || operation_id(adapter, &map)? != operation.id
        {
            return Err(format!(
                "LanguageBridge operation {} 与 schema 不一致",
                adapter.api_path
            ));
        }
    }
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

fn schema_package(package: &LanguagePackage) -> SchemaPackage {
    let mut features = package.runtime.features.clone();
    features.sort();
    SchemaPackage {
        id: package.id.clone(),
        version: package.version.clone(),
        kind: package.kind.clone(),
        backend: package.backend.clone(),
        runtime_abi: package.runtime.abi.clone(),
        runtime_min_version: package.runtime.min_version,
        runtime_max_version: package.runtime.max_version,
        runtime_entrypoint: package.runtime.entrypoint.clone(),
        runtime_features: features,
        capabilities: package.capabilities.clone(),
        limits: package.limits.clone(),
    }
}

fn default_schema_package() -> SchemaPackage {
    SchemaPackage {
        id: "unbound.bridge".to_string(),
        version: "0.0.0".to_string(),
        kind: "extension".to_string(),
        backend: "unbound".to_string(),
        runtime_abi: "hitoshizuku.language-runtime.v1".to_string(),
        runtime_min_version: 1,
        runtime_max_version: 1,
        runtime_entrypoint: "elm_language_entry".to_string(),
        runtime_features: Vec::new(),
        capabilities: Vec::new(),
        limits: PackageLimits {
            max_handles: 1,
            max_dma_bytes: 1,
            max_pending_requests: 1,
            max_heap_bytes: 1,
            max_stack_bytes: 1,
            max_threads: 1,
            max_metadata_bytes: 1,
            max_artifact_bytes: 1,
        },
    }
}

fn validate_runtime(runtime: &RuntimeRequirement) -> Result<(), String> {
    validate_runtime_abi(&runtime.abi, "runtime.abi")?;
    if runtime.min_version == 0
        || runtime.max_version == 0
        || runtime.min_version > runtime.max_version
    {
        return Err("runtime 版本范围无效".to_string());
    }
    validate_symbol(&runtime.entrypoint, "runtime.entrypoint")?;
    let mut features = BTreeSet::new();
    for feature in &runtime.features {
        validate_identifier(feature, "runtime.features", 64)?;
        if !features.insert(feature) {
            return Err(format!("runtime.features 重复项: {feature}"));
        }
    }
    Ok(())
}

fn validate_package_limits(limits: &PackageLimits) -> Result<(), String> {
    if limits.max_handles == 0
        || limits.max_dma_bytes == 0
        || limits.max_pending_requests == 0
        || limits.max_heap_bytes == 0
        || limits.max_stack_bytes == 0
        || limits.max_threads == 0
        || limits.max_metadata_bytes == 0
        || limits.max_artifact_bytes == 0
    {
        return Err("所有 package limits 必须大于 0".to_string());
    }
    if limits.max_metadata_bytes > 64 * 1024 * 1024
        || limits.max_artifact_bytes > 4 * 1024 * 1024 * 1024
    {
        return Err("package metadata/artifact limits 超出工具上限".to_string());
    }
    Ok(())
}

fn parse_artifact_signature(raw: RawArtifactSignature) -> Result<ArtifactSignature, String> {
    match raw.algorithm.as_str() {
        "none" => {
            if raw.public_key.is_some() || raw.value.is_some() {
                return Err("signature.algorithm=none 时不能提供 public_key/value".to_string());
            }
            Ok(ArtifactSignature::None)
        }
        "ed25519" => {
            let public_key = decode_hex::<32>(
                raw.public_key
                    .as_deref()
                    .ok_or_else(|| "Ed25519 signature 缺少 public_key".to_string())?,
                "signature.public_key",
            )?;
            VerifyingKey::from_bytes(&public_key)
                .map_err(|error| format!("signature.public_key 不是有效 Ed25519 公钥: {error}"))?;
            let signature = decode_hex::<64>(
                raw.value
                    .as_deref()
                    .ok_or_else(|| "Ed25519 signature 缺少 value".to_string())?,
                "signature.value",
            )?;
            Ok(ArtifactSignature::Ed25519 {
                public_key,
                signature,
            })
        }
        other => Err(format!("未知 signature.algorithm: {other}")),
    }
}

fn verify_artifact_signature(
    artifact: &Artifact,
    bytes: &[u8],
    trusted_key: Option<&[u8; 32]>,
) -> Result<(), String> {
    match &artifact.signature {
        ArtifactSignature::None => {
            if trusted_key.is_some() {
                Err(format!(
                    "artifact {} 未提供受信根要求的 Ed25519 签名",
                    artifact.path.display()
                ))
            } else {
                Ok(())
            }
        }
        ArtifactSignature::Ed25519 {
            public_key,
            signature,
        } => {
            if let Some(trusted_key) = trusted_key
                && public_key != trusted_key
            {
                return Err(format!(
                    "artifact {} 的签名公钥不在外部信任根中",
                    artifact.path.display()
                ));
            }
            let key = VerifyingKey::from_bytes(public_key).map_err(|error| {
                format!("artifact {} 公钥无效: {error}", artifact.path.display())
            })?;
            key.verify(bytes, &Signature::from_bytes(signature))
                .map_err(|_| format!("artifact {} 的 Ed25519 签名无效", artifact.path.display()))
        }
    }
}

fn canonical_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn read_package_file(root: &Path, relative: &Path, field: &str) -> Result<Vec<u8>, String> {
    validate_relative_path(relative, field)?;
    let unresolved = root.join(relative);
    let resolved = unresolved
        .canonicalize()
        .map_err(|error| format!("定位 {field} {} 失败: {error}", relative.display()))?;
    if !resolved.starts_with(root) || !resolved.is_file() {
        return Err(format!("{field} 必须解析为 package 目录内的普通文件"));
    }
    fs::read(&resolved).map_err(|error| format!("读取 {} 失败: {error}", relative.display()))
}

fn verify_digest(bytes: &[u8], expected: &str, field: &str) -> Result<(), String> {
    let actual = hex_digest(&sha256(bytes));
    if actual != expected {
        return Err(format!(
            "{field} SHA-256 不匹配: expected={expected} actual={actual}"
        ));
    }
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("创建输出目录 {} 失败: {error}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| format!("编码 schema 失败: {error}"))?;
    fs::write(path, format!("{json}\n"))
        .map_err(|error| format!("写入 {} 失败: {error}", path.display()))
}

fn schema_upgrade_error(name: &str, actual: u32, expected: u32) -> String {
    if actual < expected {
        format!(
            "{name} schema v{actual} 已停用；请迁移到 v{expected} 的固定类型图、u64 operation ID 与摘要字段"
        )
    } else {
        format!("{name} schema v{actual} 不受当前工具支持（当前 v{expected}）")
    }
}

fn validate_identifier(value: &str, field: &str, max: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        || matches!(value.as_bytes().first(), Some(b'.' | b'-' | b'0'..=b'9'))
    {
        return Err(format!("{field} 无效: {value}"));
    }
    Ok(())
}

fn validate_version(value: &str, field: &str) -> Result<(), String> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(format!("{field} 必须是 x.y.z 形式"));
    }
    Ok(())
}

fn validate_target(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("无效 target: {value}"));
    }
    Ok(())
}

fn validate_relative_string(value: &str, field: &str) -> Result<(), String> {
    if value.contains(['\\', '\0']) {
        return Err(format!("{field} 必须是安全的 UTF-8 相对路径"));
    }
    validate_relative_path(Path::new(value), field)
}

fn validate_relative_path(path: &Path, field: &str) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!("{field} 必须是不含 `.`/`..` 的安全相对路径"));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), String> {
    decode_hex::<32>(value, field).map(|_| ())
}

fn validate_runtime_abi(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        || !value.contains('.')
    {
        return Err(format!("{field} 无效: {value}"));
    }
    Ok(())
}

fn validate_symbol(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index != 0 || !byte.is_ascii_digit())
        })
    {
        return Err(format!("{field} 不是有效的链接符号: {value}"));
    }
    Ok(())
}

fn validate_link_name(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$' | b'@'))
    {
        return Err(format!("{field} 不是可移植的 ELF 链接名称: {value}"));
    }
    Ok(())
}

fn validate_capability(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 {
        return Err(format!("capability 无效: {value}"));
    }
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() < 2
        || segments.iter().any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(format!("capability 必须是小写的点分命名空间: {value}"));
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
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!("无效 operation.wire: {value}"));
    }
    Ok(())
}

fn validate_type_identifier(value: &str, field: &str) -> Result<(), String> {
    const RUST_KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do",
        "final", "gen", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield",
    ];
    const GENERATED_NAMES: &[&str] = &[
        "bool",
        "char",
        "str",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "f32",
        "f64",
        "String",
        "Vec",
        "Option",
        "Result",
        "Box",
        "CodecError",
        "OperationId",
        "OperationDescriptor",
        "KernelApi",
        "KernelBridge",
        "CapabilityHandle",
        "MmioHandle",
        "DmaHandle",
        "BufferLeaseHandle",
        "PACKAGE_ID",
        "PACKAGE_VERSION",
        "TARGET",
        "PROFILE",
        "INTERFACE_SHA256",
        "OPERATIONS",
    ];
    if value.is_empty()
        || value.len() > 96
        || RUST_KEYWORDS.contains(&value)
        || GENERATED_NAMES.contains(&value)
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index != 0 || !byte.is_ascii_digit())
        })
    {
        return Err(format!("{field} 不是可移植标识符: {value}"));
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{field} 必须是 {} 个十六进制字符", N * 2));
    }
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (hex_digit(value.as_bytes()[offset], field)? << 4)
            | hex_digit(value.as_bytes()[offset + 1], field)?;
    }
    Ok(output)
}

fn hex_digit(byte: u8, field: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(format!("{field} 必须使用小写十六进制")),
    }
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    hex_bytes(bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn stable_identity_id(domain: &[u8], value: &str) -> u64 {
    let mut input = Vec::with_capacity(domain.len() + value.len() + 1);
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(value.as_bytes());
    let digest = sha256(&input);
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes).max(1)
}

fn const_identifier(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn c_identifier(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::kernel_interface::{
        KERNEL_API_BRIDGE_ABI_V1, KernelInterfaceMixinSite, KernelInterfaceSymbol,
    };

    static TEMP_SERIAL: AtomicU64 = AtomicU64::new(0);

    fn interface() -> KernelInterfaceManifest {
        let rust_abi = "fn(u64) -> u64".to_string();
        KernelInterfaceManifest {
            target: "riscv64gc-unknown-none-elf".to_string(),
            profile: "demo".to_string(),
            bridge_abi_version: KERNEL_API_BRIDGE_ABI_V1,
            kernel_hash: [1; 32],
            interface_hash: [2; 32],
            source_hash: [3; 32],
            framework_hash: [4; 32],
            source_file_count: 1,
            metadata: BTreeMap::new(),
            support_library: "support".to_string(),
            import_library: "imports".to_string(),
            symbols: vec![KernelInterfaceSymbol {
                kind: 1,
                flags: 0,
                version: 1,
                capabilities: kernel_symbols::capability::DEVICE_DISCOVERY,
                retained_argument_mask: 0,
                interface_hash: [2; 32],
                api_path: "general.dev.demo.open".to_string(),
                item_path: "demo::open".to_string(),
                link_name: "elm_demo_open".to_string(),
                contract: "general.dev.demo@1".to_string(),
                rust_abi_hash: sha256(rust_abi.as_bytes()),
                rust_abi,
                abi_mode: "exact-rust".to_string(),
                aliases: Vec::new(),
            }],
            mixin_sites: Vec::<KernelInterfaceMixinSite>::new(),
        }
    }

    fn bridge_source() -> String {
        r#"
schema = 2
endian = "little"

[[type]]
name = "Bool"
kind = "boolean"
size = 1
align = 1
version = 1
endian = "none"
ownership = "value"
limits = {}

[[type]]
name = "Handle"
kind = "handle"
size = 8
align = 8
version = 1
endian = "little"
ownership = "handle"
limits = {}
handle_kind = "capability"

[[type]]
name = "Mode"
kind = "enum"
size = 4
align = 4
version = 1
endian = "little"
ownership = "value"
limits = {}
repr = "U32"
[[type.variant]]
name = "Read"
value = 1
[[type.variant]]
name = "Write"
value = 2

[[type]]
name = "Modes"
kind = "array"
size = 8
align = 4
version = 1
endian = "none"
ownership = "value"
limits = { max_items = 2 }
element = "Mode"
length = 2
stride = 4

[[type]]
name = "Payload"
kind = "bytes"
size = 8
align = 1
version = 1
endian = "none"
ownership = "value"
limits = { max_length = 8 }
length = 8

[[type]]
name = "Request"
kind = "struct"
size = 16
align = 8
version = 1
endian = "none"
ownership = "value"
limits = {}
[[type.field]]
name = "handle"
type = "Handle"
offset = 0
[[type.field]]
name = "mode"
type = "Mode"
offset = 8
[[type.field]]
name = "enabled"
type = "Bool"
offset = 12

[[type]]
name = "Response"
kind = "struct"
size = 8
align = 1
version = 1
endian = "none"
ownership = "value"
limits = {}
[[type.field]]
name = "payload"
type = "Payload"
offset = 0

[[type]]
name = "U32"
kind = "integer"
size = 4
align = 4
version = 1
endian = "little"
ownership = "value"
limits = { min_value = 0, max_value = 1024 }
bits = 32
signed = false

[[operation]]
api_path = "general.dev.demo.open"
wire = "device.open"
request = "Request"
response = "Response"
ownership = "none"
version = 1
capability = "device.discovery"
limits = { max_request_bytes = 16, max_response_bytes = 8 }
"#
        .to_string()
    }

    fn package_source(
        eki_hash: &str,
        eki_size: usize,
        interface_hash: &str,
        bridge_hash: &str,
    ) -> String {
        format!(
            r#"
[package]
schema = 2
id = "demo.driver"
version = "0.1.0"
kind = "driver"
backend = "native-aot"
targets = ["riscv64gc-unknown-none-elf"]
profile = "demo"
eki = "module.eki"
eki_sha256 = "{eki_hash}"
interface = "interface.schema.json"
interface_sha256 = "{interface_hash}"
bridge = "LanguageBridge.toml"
bridge_sha256 = "{bridge_hash}"

[runtime]
abi = "hitoshizuku.language-runtime.v1"
min_version = 1
max_version = 1
entrypoint = "elm_language_entry"
features = ["gc"]

[[artifact]]
path = "module.eki"
kind = "eki"
target = "riscv64gc-unknown-none-elf"
runtime_abi = "hitoshizuku.language-runtime.v1"
entrypoint = "elm_language_entry"
sha256 = "{eki_hash}"
size = {eki_size}
[artifact.signature]
algorithm = "none"

[capabilities]
requested = ["device.discovery"]

[limits]
max_handles = 32
max_dma_bytes = 1048576
max_pending_requests = 16
max_heap_bytes = 8388608
max_stack_bytes = 1048576
max_threads = 4
max_metadata_bytes = 1048576
max_artifact_bytes = 16777216
"#
        )
    }

    fn temp_dir() -> PathBuf {
        let serial = TEMP_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cargo-elm-language-package-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn v1_has_explicit_migration_error_and_unknown_fields_are_rejected() {
        let bridge = bridge_source();
        let error = BridgeDocument::parse(&bridge.replace("schema = 2", "schema = 1")).unwrap_err();
        assert!(error.contains("迁移到 v2"));
        assert!(
            BridgeDocument::parse(
                &bridge.replace("endian = \"little\"", "endian = \"little\"\nunknown = 1")
            )
            .is_err()
        );
        assert!(
            BridgeDocument::parse(&bridge.replace("kind = \"boolean\"", "kind = \"mystery\""))
                .is_err()
        );
    }

    #[test]
    fn operation_id_is_u64_stable_and_layout_sensitive() {
        let bridge = BridgeDocument::parse(&bridge_source()).unwrap();
        let map = type_map(&bridge.types);
        let id = operation_id(&bridge.operations[0], &map).unwrap();
        assert_ne!(id, 0);
        assert_eq!(id, 0xf121_ddf8_b7c6_a284);

        let changed =
            BridgeDocument::parse(&bridge_source().replace("value = 2", "value = 3")).unwrap();
        let changed_id = operation_id(&changed.operations[0], &type_map(&changed.types)).unwrap();
        assert_eq!(changed_id, 0x4ecc_7c41_09d0_2bf7);
        assert_ne!(id, changed_id);

        let mut ids = BTreeMap::new();
        register_operation_id(&mut ids, id, "first").unwrap();
        assert!(
            register_operation_id(&mut ids, id, "second")
                .unwrap_err()
                .contains("冲突")
        );
        assert!(register_operation_id(&mut ids, 0, "zero").is_err());
    }

    #[test]
    fn generated_sdk_bridge_and_c_header_are_language_neutral() {
        let bridge = BridgeDocument::parse(&bridge_source()).unwrap();
        let schema = build_schema(&interface(), None, &bridge).unwrap();
        assert_ne!(schema.operations[0].id, 0);
        let sdk = render_sdk(&schema);
        let rust_bridge = render_bridge(&schema);
        syn::parse_file(&sdk).expect("generated SDK must parse as Rust");
        syn::parse_file(&rust_bridge).expect("generated bridge must parse as Rust");
        let root = temp_dir();
        let sdk_path = root.join("sdk.rs");
        fs::write(&sdk_path, &sdk).unwrap();
        let output = std::process::Command::new("rustc")
            .args(["--edition=2024", "--crate-type=lib"])
            .arg(&sdk_path)
            .arg("-o")
            .arg(root.join("libsdk.rlib"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "generated SDK failed to compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::remove_dir_all(root).unwrap();
        assert!(sdk.contains("pub type OperationId = u64"));
        assert!(sdk.contains("CodecError::NonZeroPadding"));
        let header = render_c_header(&schema);
        assert!(header.contains("typedef uint64_t hitoshizuku_elm_operation_id"));
        assert!(header.contains("uint8_t bytes[16]"));
        let descriptor = serde_json::to_string(&CommonDescriptor::from_schema(&schema)).unwrap();
        assert!(descriptor.contains("\"operation_id\""));
        assert!(!descriptor.contains("rust_abi_sha256"));
    }

    #[test]
    fn package_manifest_requires_artifact_runtime_hash_signature_and_limits() {
        let zero = "0".repeat(64);
        let package = package_source(&zero, 1, &zero, &zero);
        assert!(LanguagePackage::parse(&package).is_ok());
        assert!(
            LanguagePackage::parse(&package.replace(
                "runtime_abi = \"hitoshizuku.language-runtime.v1\"",
                "runtime_abi = \"wrong.runtime.v1\""
            ))
            .is_err()
        );
        assert!(
            LanguagePackage::parse(
                &package.replace("algorithm = \"none\"", "algorithm = \"unknown\"")
            )
            .is_err()
        );
        assert!(
            LanguagePackage::parse(&package.replace("max_threads = 4", "max_threads = 0")).is_err()
        );
    }

    #[test]
    fn artifact_signature_covers_the_exact_artifact_bytes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let bytes = b"artifact bytes";
        let artifact = Artifact {
            path: PathBuf::from("module.eki"),
            kind: "eki".to_string(),
            target: "riscv64gc-unknown-none-elf".to_string(),
            runtime_abi: "hitoshizuku.language-runtime.v1".to_string(),
            entrypoint: "elm_language_entry".to_string(),
            sha256: hex_digest(&sha256(bytes)),
            size: bytes.len() as u64,
            signature: ArtifactSignature::Ed25519 {
                public_key: key.verifying_key().to_bytes(),
                signature: key.sign(bytes).to_bytes(),
            },
        };
        verify_artifact_signature(&artifact, bytes, None).unwrap();
        assert!(verify_artifact_signature(&artifact, b"replaced bytes", None).is_err());
    }

    #[test]
    fn package_check_verifies_real_files_schema_bridge_and_artifact() {
        let root = temp_dir();
        let bridge_text = bridge_source();
        fs::write(root.join("LanguageBridge.toml"), &bridge_text).unwrap();
        let bridge_hash = hex_digest(&sha256(bridge_text.as_bytes()));
        let mut fingerprint = crate::default_abi_fingerprint(elm::ElmEbiArch::Riscv64);
        fingerprint.kernel_api_profile_hash = [2; 32];
        fingerprint.kernel_api_bridge_abi_version = 1;
        let eki = crate::eki_image_with_hash(
            elm::ElmEbiArch::Riscv64,
            &[
                crate::PackerBlock::new(
                    crate::BLOCK_MANIFEST,
                    crate::manifest_block("demo", "0.1.0", elm::ElmKind::Driver).unwrap(),
                ),
                crate::PackerBlock::new(
                    crate::BLOCK_ABI_FINGERPRINT,
                    crate::abi_fingerprint_block(&fingerprint),
                ),
                crate::PackerBlock::new(
                    crate::BLOCK_LIFECYCLE_HOOKS,
                    crate::lifecycle_hooks_block(),
                ),
            ],
        );
        fs::write(root.join("module.eki"), &eki).unwrap();
        let eki_hash = hex_digest(&sha256(&eki));
        let placeholder = "0".repeat(64);
        let initial_package_text = package_source(&eki_hash, eki.len(), &placeholder, &bridge_hash);
        let package = LanguagePackage::parse(&initial_package_text).unwrap();
        let bridge = BridgeDocument::parse(&bridge_text).unwrap();
        let schema = build_schema(&interface(), Some(&package), &bridge).unwrap();
        let schema_text = format!("{}\n", serde_json::to_string_pretty(&schema).unwrap());
        fs::write(root.join("interface.schema.json"), &schema_text).unwrap();
        let schema_hash = hex_digest(&sha256(schema_text.as_bytes()));
        fs::write(
            root.join("LanguagePackage.toml"),
            package_source(&eki_hash, eki.len(), &schema_hash, &bridge_hash),
        )
        .unwrap();

        check_language_package(&root).unwrap();
        fs::write(root.join("module.eki"), [0u8]).unwrap();
        assert!(
            check_language_package(&root)
                .unwrap_err()
                .contains("SHA-256")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
