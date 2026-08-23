# `src` 源码目录

这里是 `cargo-elm` 的主机端实现。代码负责把内核导出的接口元数据转换为 ELM
工程可以消费的接口包，并协调模块的检查、构建和 EKI/EBI 产物导出。

## 文件职责

- `main.rs`：Cargo 子命令入口和命令行分发。新增命令时先在这里登记参数和错误边界。
- `project.rs`：解析 `elm.toml`、定位内核 checkout、同步 framework，并调用 Cargo
  完成项目级检查与构建。
- `kernel_interface.rs`：读取内核 API 目录、解析接口元数据、生成稳定的接口清单和
  符号探针。这里的接口格式属于内核与模块之间的契约，修改前需要同步内核文档。
- `build_set.rs`：解析模块集合和配置，计算依赖顺序，并为一组模块复用同一个接口、
  framework 和 Cargo 缓存。
- `rust_metadata.rs`：解析 Rust section 中的 ELM 声明，整理导入、导出、provider、
  extension 和 kernel mixin 元数据。
- `kernel-api-crates.txt`：内核可被 ELM 引用的 crate 目录快照。它必须与锁定的内核
  revision 一起更新，不能单独扩展为任意 crate 搜索。

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
