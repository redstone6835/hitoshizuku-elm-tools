# Hitoshizuku ELM 工具

本仓库提供 `cargo-elm`：用于生成内核接口包、校验 ELM 工程、构建模块集合和
导出 EKI/EBI 产物的主机端 Cargo 子命令。它不是内核 workspace 的成员。

本仓库从内核仓库提交
[`46c15e09`](https://github.com/redstone6835/hitoshizuku/commit/46c15e095e66eb9dbf6a6102f7aed6628899f87a)
拆分；此前历史仍由内核仓库保存。

## 安装

```sh
cargo install --git https://github.com/redstone6835/hitoshizuku-elm-tools cargo-elm
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
```

接口包和模块构建必须使用同一内核提交；不要把接口工具的依赖升级到未验证的
内核 revision。工具仓库内的 `src/kernel-api-crates.txt` 是接口目录快照，内核
提交中的同名文件若发生变化，应随工具版本一起更新。

## 许可

GPLv3，见仓库根目录的 `LICENSE`。
