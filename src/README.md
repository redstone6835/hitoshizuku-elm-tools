# `src` 源码目录

这里是 `cargo-elm` 的主机端实现。代码负责把内核导出的接口元数据转换为 ELM
工程可以消费的接口包，并协调模块的检查、构建和 EKI/EBI 产物导出。

## 文件职责

- `main.rs`：Cargo 子命令入口和命令行分发。新增命令时先在这里登记参数和错误边界。
- `project.rs`：解析 `elm.toml`、定位内核 checkout、同步 framework，并调用 Cargo
  完成项目级检查与构建。
- `kernel_interface.rs`：读取内核 API 目录、解析接口元数据、生成稳定的接口清单和
  符号探针。这里的接口格式属于内核与模块之间的契约，修改前需要同步内核文档。
- `language_package.rs`：严格解析 `LanguagePackage.toml` 和 `LanguageBridge.toml`，
  将 EKI Profile 转换为语言无关 schema v2；验证固定类型图，生成稳定非零 `u64`
  operation ID、Rust wire codec、通用 JSON descriptor、C header 和 Rust bridge，并
  对真实 artifact 执行摘要/大小/签名校验。它不会从 Rust ABI 文本猜测函数签名，也不会
  生成任意函数指针。
- `build_set.rs`：解析模块集合和配置，计算依赖顺序，并为一组模块复用同一个接口、
  framework 和 Cargo 缓存。
- `rust_metadata.rs`：解析 Rust section 中的 ELM 声明，整理导入、导出、provider、
  extension 和 kernel mixin 元数据。
- `ui.rs`：Rust/Cargo 风格的彩色状态标签、帮助文本和交互式配置提示；支持
  `--color`、`CARGO_TERM_COLOR` 和 `NO_COLOR`。
- `disasm.rs`：校验 EKI、恢复运行时段布局并生成临时 ELF，调用 GNU/LLVM `objdump`
  输出带符号的 Code 段反汇编。
- `kernel-api-crates.txt`：内核可被 ELM 引用的 crate 目录快照。它必须与锁定的内核
  revision 一起更新，不能单独扩展为任意 crate 搜索。

## 语言包生成

`profile-export` 生成接口清单后，可以为外置语言 runtime 生成稳定的中立 schema：

```sh
cargo elm interface-schema build/elm-interface/riscv64/manifest.txt \
  --package LanguagePackage.toml \
  --adapters LanguageBridge.toml \
  --output interface.schema.json
cargo elm descriptor build/elm-interface/riscv64/manifest.txt \
  --package LanguagePackage.toml --adapters LanguageBridge.toml \
  --output generated/descriptor
cargo elm bridge build/elm-interface/riscv64/manifest.txt \
  --adapters LanguageBridge.toml --output generated/bridge.rs
cargo elm sdk build/elm-interface/riscv64/manifest.txt \
  --package LanguagePackage.toml --adapters LanguageBridge.toml \
  --output generated/rust-sdk
cargo elm package-check .

# x86_64 接口包使用相同的命令，目标目录为 build/elm-interface/x86_64：
cargo elm interface-schema build/elm-interface/x86_64/manifest.txt \
  --package LanguagePackage.toml --adapters LanguageBridge.toml \
  --output interface.schema.json
```

`LanguagePackage.toml`、`LanguageBridge.toml` 均使用 schema v2 严格字段校验；未知字段、
未知类型种类和旧 schema 会被拒绝。adapter 的每个 `api_path` 必须在 EKI Profile 中存在，
并明确请求/回复固定布局、版本、ownership、字节上限和可选 capability。生成代码只传递
`u64` operation ID、边界检查后的 byte buffer 和不透明资源句柄，不会把物理地址、裸指针
或未经登记的 Rust 类型跨越 ELM 边界。格式细节见根目录 `LANGUAGE-PACKAGE.md`。

## EKI 反汇编

调试已构建模块时可以使用 objdump 风格的命令：

```sh
cargo elm objdump build/x86_64/modules/example.eki
cargo elm disassemble build/x86_64/modules/example.eki \
  --arch x86_64 --disassembler-options=intel
```

`objdump`、`disasm` 和 `disassemble` 是同一个命令。单变体 EKI 直接给出文件路径；多变体
文件默认逐个输出，也可以用 `--variant <索引>` 只选择一个。`--segment <索引>`（别名
`--section`）选择 Code 段，`--symbol <名称>` 可重复选择已登记的代码符号，也接受 GNU 风格
`--disassemble=<名称>` 或 LLVM 风格 `--disassemble-symbols=<名称>[,...]`；地址过滤使用
`--start-address`、`--stop-address`，装载地址修正使用 `--base-address` 或
`--adjust-vma`。`--no-show-raw-insn` 隐藏原始字节，`-M`/`--disassembler-options` 和
`--tool` 分别传递反汇编器选项、指定 objdump 路径。

该命令先通过 EKI 解析器校验文件，再把 Code 段和符号位置写入临时 ELF，最后调用 GNU 或
LLVM `objdump`；临时文件会在命令结束时清理。EKI 的地址是镜像相对地址，段间按内核运行时
页对齐规则布置，因此默认输出与模块装载布局一致。目标为 `any` 的 EKI 必须显式指定
`--arch`；系统需要安装支持所选架构的 `objdump`，metadata-only EKI 因没有 Code 段而不能
反汇编。

## 本地开发

在仓库根目录运行：

```sh
cargo check --locked
cargo test --locked
cargo run --locked -- --help
```

从独立目录调用时，设置 `HITOSHIZUKU_KERNEL_ROOT` 指向目标内核源码；接口工具、
接口包和最终内核镜像必须来自同一个内核提交。生成文件写入调用方指定的输出目录，
不应提交到本目录。

## 边界

本目录不包含内核实现、Native runtime 或 SOYO 链接器。内核 ABI 的权威定义在核心
仓库，SOYO 编码与链接逻辑在 `hitoshizuku-soyo-linker`；这里只消费它们的公开契约。
