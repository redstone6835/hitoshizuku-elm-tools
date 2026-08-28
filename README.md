# Hitoshizuku ELM 工具

本仓库提供 `cargo-elm`：用于生成内核接口包、校验 ELM 工程、构建模块集合和
导出 EKI/EBI 产物的主机端 Cargo 子命令。它不是内核 workspace 的成员。

本仓库从内核仓库提交
[`46c15e09`](https://github.com/redstone6835/hitoshizuku/commit/46c15e095e66eb9dbf6a6102f7aed6628899f87a)
拆分；此前历史仍由内核仓库保存。

## 安装

```sh
cargo install --locked --git https://github.com/redstone6835/hitoshizuku-elm-tools cargo-elm
```

开发本仓库时可直接运行：

```sh
cargo install --path . --force
```

## 指定内核源码

在内核 checkout 中运行时，工具会从当前目录自动定位源码。由其他目录直接调用时，设置
`HITOSHIZUKU_KERNEL_ROOT` 指向与目标内核镜像对应的 checkout：

```sh
export HITOSHIZUKU_KERNEL_ROOT=$HOME/src/hitoshizuku
cargo elm profile-export build/loongarch64/kernel \
  --target loongarch64-unknown-none \
  --profile hitoshizuku-default \
  --output build/elm-interface/loongarch64
# x86_64 内核使用 x86_64-unknown-none，接口目录可按目标名保存：
cargo elm profile-export build/x86_64/kernel \
  --target x86_64-unknown-none \
  --profile hitoshizuku-default \
  --output build/elm-interface/x86_64
```

## 生成目标 Profile

ELM 模块不会隐式编译另一个仓库中的内核。首次为某个架构构建模块，或内核的公共
framework 发生变化后，应先在 Hitoshizuku 内核仓库生成该目标的接口包：

```sh
cd "$HITOSHIZUKU_KERNEL_ROOT"
cargo xtask modules --target riscv64gc-unknown-none-elf
# 或：cargo xtask modules --target loongarch64-unknown-none
# 或：cargo xtask modules --target x86_64-unknown-none
```

随后回到独立 ELM 工程同步接口并构建：

```sh
cargo elm sync .
cargo elm build . --arch riscv64 --unsigned
# x86_64 ELM 构建：
cargo elm build . --arch x86_64 --unsigned
```

首次 `sync` 后，`build` 和 `check` 会复用工程中的 `.elm/kernel-interface`，不要求每次
重新设置内核路径；需要发现新 Profile 或刷新接口包时，再设置内核路径并执行 `sync`。

不同架构的接口包必须由同一内核提交和同一 framework 快照生成。工具会拒绝混用
摘要不同的 Profile，避免模块在开发时看到与最终内核不一致的 Rust API。

## 命令帮助和输出

使用 Rust/Cargo 风格的帮助查看所有子命令、参数、默认值和可选值：

```sh
cargo elm --help
cargo elm build --help
cargo elm help image-bundle
```

终端输出默认自动启用颜色；可以显式选择颜色策略：

```sh
cargo elm --color auto build --help
cargo elm --color always check . --arch riscv64
cargo elm --color never doctor .
```

`--color` 可选 `auto`、`always`、`never`，也支持标准环境变量
`CARGO_TERM_COLOR=auto|always|never`；`--no-color` 是 `--color never` 的快捷写法；设置
`NO_COLOR` 会关闭自动颜色（显式 `--color always` 仍可强制开启）。`inspect` 的
`key=value` 输出保持无装饰，适合脚本读取。

## 语言无关 SDK

接口工具可以把内核 EKI Profile 转换为外置 runtime 可消费的中立 schema v2。类型图
明确记录整数、布尔值、定长 bytes/array、struct、enum 和不透明 handle 的大小、对齐、
偏移、端序、ownership、限制和版本，不从 Rust 类型名或 ABI 文本推断 wire layout：

```sh
cargo elm interface-schema <manifest.txt> \
  --package LanguagePackage.toml --adapters LanguageBridge.toml \
  --output interface.schema.json
cargo elm descriptor <manifest.txt> --package LanguagePackage.toml \
  --adapters LanguageBridge.toml --output generated/descriptor
cargo elm bridge <manifest.txt> --adapters LanguageBridge.toml \
  --output generated/bridge.rs
cargo elm sdk <manifest.txt> --package LanguagePackage.toml \
  --adapters LanguageBridge.toml --output generated/rust-sdk
cargo elm package-check <语言包目录>
```

`LanguagePackage.toml` 声明 package 身份、runtime ABI、entrypoint、目标、profile、
artifact、SHA-256、签名、capability 和资源上限；`LanguageBridge.toml` 逐项登记类型图
以及 API path 到 wire operation 的映射。operation ID 是 domain-separated SHA-256
前 8 字节的小端 `u64` 截断值，零值和同一 schema 内的碰撞会被拒绝。类型布局或 operation 契约
变化都会改变 ID。

`descriptor` 生成完整审计 schema、去除 Rust 符号细节的通用 JSON descriptor 和只含
opaque byte layout 的 C header；`sdk` 额外生成 `no_std` Rust codec。生成代码不猜测
`rust_abi`，也不暴露裸指针或物理地址；capability、MMIO、DMA 和 buffer lease 通过
`handle_kind` 明确的不透明 `u64` token 传递。

`package-check` 会读取真实文件并核对 bridge/schema/EKI/artifact 的 SHA-256、artifact
大小、Ed25519 签名、runtime ABI、entrypoint、target/profile、类型图和重新计算出的
operation ID。它还会拒绝越出 package 目录的路径或符号链接。完整格式和迁移说明见
[`LANGUAGE-PACKAGE.md`](LANGUAGE-PACKAGE.md)。schema v1 不会被静默解释为 v2。

接口包和模块构建必须使用同一内核提交；不要把接口工具的依赖升级到未验证的
内核 revision。工具仓库内的 `src/kernel-api-crates.txt` 是接口目录快照，内核
提交中的同名文件若发生变化，应随工具版本一起更新。

## 目录

- [`src/README.md`](src/README.md)：命令入口、工程改写、接口导出和 build-set；
- [`LANGUAGE-PACKAGE.md`](LANGUAGE-PACKAGE.md)：语言无关 package、IDL、descriptor 和校验规范；
- `src/kernel_interface.rs`：内核符号和 rlib metadata 处理；
- `src/project.rs`：ELM 工程发现、临时 framework 和 manifest 保护；
- `src/build_set.rs`：按 `Modules.toml` 解析并构建模块集合；
- `src/rust_metadata.rs`：Rust crate 元数据和接口快照辅助。

## 许可

GPLv3，见仓库根目录的 `LICENSE`。
