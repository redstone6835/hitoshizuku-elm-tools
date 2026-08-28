# 语言无关 ELM Package 与接口格式

本文定义 `cargo-elm` schema v2 的主机端格式。格式只描述稳定 wire 数据、runtime 契约和
artifact 完整性，不规定某一种实现语言的对象布局、调用约定或运行时内部结构。

## 生成流程

```sh
cargo elm profile-export <kernel.elf> --target <target> \
  --profile <profile> --output build/interface
cargo elm interface-schema build/interface/manifest.txt \
  --package LanguagePackage.toml --adapters LanguageBridge.toml \
  --output interface.schema.json
cargo elm descriptor build/interface/manifest.txt \
  --package LanguagePackage.toml --adapters LanguageBridge.toml \
  --output generated/descriptor
cargo elm sdk build/interface/manifest.txt \
  --package LanguagePackage.toml --adapters LanguageBridge.toml \
  --output generated/rust-sdk
cargo elm package-check . --trusted-key <发行方 Ed25519 公钥十六进制>
```

`interface-schema` 输出含内核符号审计信息的完整 schema。`descriptor` 输出：

- `interface.schema.json`：完整 schema；
- `interface.descriptor.json`：不含 Rust 符号实现细节的通用描述；
- `interface.h`：以固定大小 byte struct 表示 wire 类型的 C header。

`interface.schema.json` 的 `interface` 节还包含可直接填入
`LanguageArtifactIdentityV2` 的 `package_id`、`artifact_id`、`package_digest`、
`artifact_digest` 和 `interface_digest`。其中 `package_digest` 使用规范化清单计算，
不包含 `interface.schema.json` 自身的文件摘要，避免清单摘要与 schema 文件互相包含；
`interface_digest` 是 EKI Kernel API Profile 摘要，`package.interface_sha256` 仍单独
保护 schema 文件完整性。所有 ID 使用 domain-separated SHA-256 的小端前 64 位，零值
会映射为 1。

`sdk` 还会生成 `lib.rs`，其中包含 `no_std` Rust codec、padding/enum/bool 校验、operation
常量和调用 trait。

## `LanguagePackage.toml`

所有字段均为严格字段；拼错或额外字段会导致解析失败。v1 已停用，必须显式升级到 v2。

```toml
[package]
schema = 2
id = "example.driver"
version = "0.1.0"
kind = "driver"
backend = "native-aot"
targets = ["x86_64-unknown-none"]
profile = "hitoshizuku-default"
eki = "artifacts/example.eki"
eki_sha256 = "<64 个小写十六进制字符>"
interface = "interface.schema.json"
interface_sha256 = "<64 个小写十六进制字符>"
bridge = "LanguageBridge.toml"
bridge_sha256 = "<64 个小写十六进制字符>"

[runtime]
abi = "hitoshizuku.language-runtime.v1"
min_version = 1
max_version = 1
entrypoint = "elm_language_entry"
features = ["gc"]

[[artifact]]
path = "artifacts/example.eki"
kind = "eki"
target = "x86_64-unknown-none"
runtime_abi = "hitoshizuku.language-runtime.v1"
entrypoint = "elm_language_entry"
sha256 = "<64 个小写十六进制字符>"
size = 1048576
[artifact.signature]
algorithm = "ed25519"
public_key = "<32 字节公钥的小写十六进制>"
value = "<64 字节签名的小写十六进制>"

[capabilities]
requested = ["device.discovery", "device.dma"]

[limits]
max_handles = 128
max_dma_bytes = 67108864
max_pending_requests = 64
max_heap_bytes = 134217728
max_stack_bytes = 2097152
max_threads = 8
max_metadata_bytes = 4194304
max_artifact_bytes = 268435456
```

`artifact.kind` 可选 `eki`、`elf`、`archive`、`blob`。签名算法可选 `ed25519` 或显式
`none`；`none` 不允许携带公钥和签名值。每个 target 至少有一个 artifact，`package.eki`
必须指向一个 `kind = "eki"` 的 artifact。artifact 的 runtime ABI 和 entrypoint 必须与
`[runtime]` 一致。

所有文件路径必须是 package 目录内不含 `.`、`..` 的相对路径。`package-check` 解析符号
链接后的真实路径，拒绝逃逸 package 目录的文件。

## `LanguageBridge.toml`

文件顶层固定为：

```toml
schema = 2
endian = "little"
```

每个 `[[type]]` 都必须声明 `name`、`kind`、`size`、`align`、`version`、`endian`、
`ownership` 和 `limits`。`size` 最大为 192 字节，`align` 必须是 1 到 64 的二次幂，
`version` 不能为零。`ownership` 可选 `value`、`owned`、`borrowed`、`lease`、`handle`。

整数与布尔值：

```toml
[[type]]
name = "U32"
kind = "integer"
size = 4
align = 4
version = 1
endian = "little"
ownership = "value"
limits = { min_value = 0, max_value = 4096 }
bits = 32
signed = false

[[type]]
name = "Bool"
kind = "boolean"
size = 1
align = 1
version = 1
endian = "none"
ownership = "value"
limits = {}
```

定长 bytes、array 和 struct：

```toml
[[type]]
name = "Payload"
kind = "bytes"
size = 64
align = 1
version = 1
endian = "none"
ownership = "value"
limits = { max_length = 64 }
length = 64

[[type]]
name = "Words"
kind = "array"
size = 16
align = 4
version = 1
endian = "none"
ownership = "value"
limits = { max_items = 4 }
element = "U32"
length = 4
stride = 4

[[type]]
name = "Request"
kind = "struct"
size = 72
align = 8
version = 1
endian = "none"
ownership = "value"
limits = {}
[[type.field]]
name = "resource"
type = "ResourceHandle"
offset = 0
[[type.field]]
name = "payload"
type = "Payload"
offset = 8
```

struct 字段必须按不重叠的偏移排列，并满足字段对齐；尾部大小必须满足 struct 对齐。类型图
不能递归。array 的 `stride` 不得小于 element 大小并且必须满足 element 对齐。codec 要求
所有显式 padding 为零。

enum 与 handle：

```toml
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
name = "ResourceHandle"
kind = "handle"
size = 8
align = 8
version = 1
endian = "little"
ownership = "handle"
limits = {}
handle_kind = "capability"
```

`handle_kind` 可选 `capability`、`mmio`、`dma`、`buffer-lease`、`opaque`。handle 是由内核
验证的不透明 `u64` token，不表示裸指针、虚拟地址或物理地址。

operation 将类型图连接到经过审核的 EKI API：

```toml
[[operation]]
api_path = "general.dev.example.request"
wire = "device.request"
request = "Request"
response = "Response"
ownership = "none"
version = 1
capability = "device.discovery"
limits = { max_request_bytes = 72, max_response_bytes = 8 }
```

`ownership` 可选 `none`、`borrowed`、`returns-owned`、`consumes`、`inout`。当前 wire 类型是
定长布局，因此 request/response byte limit 必须精确等于相应类型大小。capability 若存在，
必须同时出现在 package 的 `capabilities.requested` 中。

## Operation ID

operation ID 使用 `sha256-trunc64-le-nonzero-v2`：

1. 写入 domain `HITOSHIZUKU-ELM-OPERATION-ID-U64-V2\0`；
2. 以长度前缀编码 API path、wire 名称、ownership、capability；
3. 以小端编码 operation version 和 request/response 限制；
4. 递归编码 request/response 的完整类型布局、限制、版本、字段、enum 值和 handle kind；
5. 计算 SHA-256，将前 8 字节解释为小端 `u64`。

结果为零时拒绝生成；同一 schema 中两个 operation 得到同一 ID 时报告碰撞并拒绝生成。
测试中固定了基础类型图与 enum 变化后的两个 golden vector，防止算法被无意修改。

## `package-check` 的保证

`cargo elm package-check <目录>` 会执行以下检查：

- 清单、bridge 和 schema 均为严格 schema v2；
- interface、bridge、EKI 和全部 artifact 的真实 SHA-256 与清单一致；
- artifact 真实大小、包级资源上限、runtime ABI 和 entrypoint 一致；
- Ed25519 签名直接覆盖 artifact 的完整字节；
- EKI 可由核心 EKI parser 解析；
- package target/profile/capability 与 schema 一致；
- bridge 类型图和 operation 与 schema 完全一致；
- 每个 operation ID 从类型图重新计算，且符号快照对应同一个导出 API；
- 引用文件解析后仍位于 package 目录内。

默认不提供发布者信任根，只能证明文件摘要、格式和清单内公钥对应的自签名是自洽的，不能
证明该公钥属于项目发行方。发布或安装流程必须从项目外部信任库读取公钥，并传入：

```sh
cargo elm package-check <目录> --trusted-key <64 个小写十六进制字符>
```

提供 `--trusted-key` 后，所有 artifact 都必须使用该 Ed25519 公钥签名，未签名 artifact
或其它公钥会被拒绝。信任库、包签名策略和撤销列表属于发行系统，不由 package 清单自证。

SHA-256 和签名字段不是生成器的占位提示。发布包前必须对最终 artifact 和最终 schema 重新
计算它们；修改任一被哈希文件后，旧清单必须校验失败。
