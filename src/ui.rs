use std::env;
use std::io::{self, IsTerminal, Write};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(format!(
                "无效的颜色模式 {other:?}；可选值为 auto、always 或 never"
            )),
        }
    }

    pub(crate) fn from_environment() -> Self {
        if env::var_os("NO_COLOR").is_some() {
            return Self::Never;
        }
        env::var("CARGO_TERM_COLOR")
            .ok()
            .and_then(|value| Self::parse(&value).ok())
            .unwrap_or(Self::Auto)
    }
}

pub(crate) struct Ui {
    color: bool,
}

static UI: OnceLock<Ui> = OnceLock::new();

pub(crate) fn init(choice: ColorChoice) {
    let color = match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => auto_color_enabled(),
    };
    let _ = UI.set(Ui { color });
}

pub(crate) fn current() -> &'static Ui {
    UI.get_or_init(|| {
        let choice = ColorChoice::from_environment();
        let color = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => auto_color_enabled(),
        };
        Ui { color }
    })
}

fn auto_color_enabled() -> bool {
    env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal() && io::stderr().is_terminal()
}

impl Ui {
    pub(crate) fn color_enabled(&self) -> bool {
        self.color
    }

    fn paint(&self, code: &str, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn label(&self, code: &str, text: &str) -> String {
        self.paint(code, text)
    }

    pub(crate) fn info(&self, message: impl AsRef<str>) {
        println!("{} {}", self.label("36", "info:"), message.as_ref());
    }

    pub(crate) fn success(&self, message: impl AsRef<str>) {
        println!("{} {}", self.label("32", "success:"), message.as_ref());
    }

    pub(crate) fn warning(&self, message: impl AsRef<str>) {
        eprintln!("{} {}", self.label("33", "warning:"), message.as_ref());
    }

    pub(crate) fn error(&self, message: impl AsRef<str>) {
        eprintln!("{} {}", self.label("31", "error:"), message.as_ref());
    }

    pub(crate) fn heading(&self, message: impl AsRef<str>) {
        println!("{}", self.paint("1;36", message));
    }

    pub(crate) fn section(&self, message: impl AsRef<str>) {
        println!("\n{}", self.paint("1", message));
    }

    pub(crate) fn command(&self, syntax: &str, description: &str) {
        println!("  {}  {}", self.paint("36", syntax), description);
    }

    pub(crate) fn option(&self, syntax: &str, description: &str) {
        println!("  {}  {}", self.paint("33", syntax), description);
    }

    pub(crate) fn note(&self, message: impl AsRef<str>) {
        println!("{}", self.paint("2", message));
    }

    pub(crate) fn prompt(&self, message: &str) -> io::Result<()> {
        print!("{}", self.paint("36", message));
        io::stdout().flush()
    }
}

pub(crate) fn help(command: Option<&str>) -> bool {
    let ui = current();
    match command {
        None => {
            global_help(ui);
            true
        }
        Some("new") => command_help(
            ui,
            "new",
            "cargo elm new <目录> --name <名称> --kind <类型> --source <标识>",
            "创建一个带 Elm.toml、Cargo.toml 和最小源码的 ELM 工程。",
            &[
                ("<目录>", "必选目标目录；目录必须不存在或为空。"),
                (
                    "--name <名称>",
                    "必选；ELM manifest 名称，同时用于生成 Cargo 包名。",
                ),
                (
                    "--kind <类型>",
                    "必选；允许值：manager、service、driver、extension、filesystem、network、debug、other。",
                ),
                ("--source <标识>", "必选稳定源标识，用于镜像签名和审计。"),
            ],
        ),
        Some("sync") => command_help(
            ui,
            "sync",
            "cargo elm sync [工程目录]",
            "同步 ELM framework、内核接口包和源码投影。默认目录为当前目录。",
            &[("[工程目录]", "可选；默认 `.`。")],
        ),
        Some("check") => command_help(
            ui,
            "check",
            "cargo elm check [工程目录] [--arch <架构>]",
            "按选定 Kernel API Profile 执行宿主侧 Cargo 检查，不生成 EKI。",
            &[
                ("[工程目录]", "可选；默认 `.`。"),
                (
                    "--arch <架构>",
                    "可选值：riscv64、loongarch64、all；默认 `all`。",
                ),
            ],
        ),
        Some("test") => command_help(
            ui,
            "test",
            "cargo elm test [工程目录]",
            "运行 ELM 工程的开发侧测试。默认目录为当前目录。",
            &[("[工程目录]", "可选；默认 `.`。")],
        ),
        Some("doctor") => command_help(
            ui,
            "doctor",
            "cargo elm doctor [工程目录]",
            "诊断 manifest、framework、接口包和目标配置，不执行正式镜像构建。",
            &[("[工程目录]", "可选；默认 `.`。")],
        ),
        Some("profile-export") => command_help(
            ui,
            "profile-export",
            "cargo elm profile-export <内核 ELF> --target <三元组> --profile <标识> --output <目录> [--cargo-profile <名称>]",
            "从已构建的内核 ELF 导出精确 Kernel API Profile 和 rlib metadata。",
            &[
                ("<内核 ELF>", "必选；目标架构的 kernel ELF 文件。"),
                (
                    "--target <三元组>",
                    "必选；允许值：loongarch64-unknown-none、riscv64gc-unknown-none-elf。",
                ),
                (
                    "--profile <标识>",
                    "必选；要导出的 Kernel API Profile 名称。",
                ),
                (
                    "--cargo-profile <名称>",
                    "Cargo 构建 profile；可选，默认 `release`。",
                ),
                (
                    "--output <目录>",
                    "必选；接口 manifest、metadata 和支持归档的输出目录。",
                ),
            ],
        ),
        Some("symbol-probe") => command_help(
            ui,
            "symbol-probe",
            "cargo elm symbol-probe <接口 manifest> <输出.rs>",
            "根据接口 manifest 生成 Rust 内核符号探针源码。",
            &[
                ("<接口 manifest>", "profile-export 生成的 `manifest.txt`。"),
                ("<输出.rs>", "生成的 Rust 源文件路径。"),
            ],
        ),
        Some("interface-schema") => command_help(
            ui,
            "interface-schema",
            "cargo elm interface-schema <manifest.txt> [--package <LanguagePackage.toml>] --adapters <LanguageBridge.toml> --output <interface.schema.json>",
            "从 EKI 导出的 Kernel API Profile 和严格类型图生成 schema v2。operation ID 是固定的非零 u64。",
            &[
                ("<manifest.txt>", "profile-export 生成的内核接口清单。"),
                (
                    "--package <LanguagePackage.toml>",
                    "可选语言包；校验目标、profile、capability 和资源上限。",
                ),
                (
                    "--adapters <LanguageBridge.toml>",
                    "必选 adapter/IDL；声明固定类型布局，每个 operation 必须对应 EKI 导出的 API。",
                ),
                ("--output <interface.schema.json>", "必选 schema 输出路径。"),
            ],
        ),
        Some("descriptor") => command_help(
            ui,
            "descriptor",
            "cargo elm descriptor <manifest.txt> --package <LanguagePackage.toml> --adapters <LanguageBridge.toml> --output <目录>",
            "生成语言无关 JSON descriptor、完整审计 schema 和使用 opaque byte layout 的 C header。",
            &[
                ("<manifest.txt>", "Kernel API Profile 接口清单。"),
                (
                    "--package <LanguagePackage.toml>",
                    "必选 schema v2 语言包清单。",
                ),
                (
                    "--adapters <LanguageBridge.toml>",
                    "必选 schema v2 类型图和 operation 映射。",
                ),
                (
                    "--output <目录>",
                    "输出 interface.schema.json、interface.descriptor.json 和 interface.h。",
                ),
            ],
        ),
        Some("sdk") => command_help(
            ui,
            "sdk",
            "cargo elm sdk <manifest.txt> --package <LanguagePackage.toml> --adapters <LanguageBridge.toml> --output <目录>",
            "生成不依赖新语言 runtime 的 Rust 固定布局 codec，并同时输出通用 descriptor 和 C header。",
            &[
                ("<manifest.txt>", "Kernel API Profile 接口清单。"),
                ("--package <LanguagePackage.toml>", "必选语言包 manifest。"),
                (
                    "--adapters <LanguageBridge.toml>",
                    "必选、经过审核的 operation adapter 注册表。",
                ),
                (
                    "--output <目录>",
                    "必选；生成 lib.rs、两种 JSON descriptor 和 interface.h。",
                ),
            ],
        ),
        Some("bridge") => command_help(
            ui,
            "bridge",
            "cargo elm bridge <manifest.txt> --adapters <LanguageBridge.toml> --output <bridge.rs>",
            "生成语言无关 Rust bridge；只暴露显式 operation 描述和安全调用 trait，不猜测 Rust ABI。",
            &[
                ("<manifest.txt>", "Kernel API Profile 接口清单。"),
                ("--adapters <LanguageBridge.toml>", "必选 adapter 注册表。"),
                ("--output <bridge.rs>", "必选 bridge Rust 源文件路径。"),
            ],
        ),
        Some("package-check") => command_help(
            ui,
            "package-check",
            "cargo elm package-check <语言包目录> [--trusted-key <公钥十六进制>]",
            "严格校验 schema v2 清单、bridge、所有 artifact 的大小/摘要/签名以及 EKI。",
            &[
                (
                    "<语言包目录>",
                    "包含 LanguagePackage.toml 及其相对路径所引用 bridge、schema、EKI 和 artifact 的目录。",
                ),
                (
                    "--trusted-key <公钥十六进制>",
                    "可选的外部 Ed25519 信任根；提供后要求每个 artifact 使用该公钥签名。未提供时只做完整性和自签名校验，不证明发布者身份。",
                ),
            ],
        ),
        Some("build") => command_help(
            ui,
            "build",
            "cargo elm build <工程目录> --arch <架构> (--unsigned | --key <种子> --epoch <数字>) [--features <列表>]",
            "构建 ELM Rust PIE，并打包为带 ABI、重定位和可选签名的 EKI。",
            &[
                ("<工程目录>", "包含 Elm.toml 的工程目录。"),
                ("--arch <架构>", "必选；可选值：riscv64、loongarch64、all。"),
                (
                    "--unsigned",
                    "生成未签名镜像；不能与 `--key` 或 `--epoch` 同时使用。",
                ),
                ("--key <种子>", "32 字节 Ed25519 私钥种子文件。"),
                (
                    "--epoch <数字>",
                    "非零发布 epoch；与 `--key` 一起启用签名。",
                ),
                (
                    "--features <列表>",
                    "可选 Cargo feature，使用逗号分隔；名称只能含小写字母、数字、`-`、`_`。",
                ),
                (
                    "模式限制",
                    "manifest mode=y（集成）或 mode=n（禁用）时不能使用 --unsigned、--key、--epoch；mode=m 才构建 EKI。",
                ),
            ],
        ),
        Some("build-set") => command_help(
            ui,
            "build-set",
            "cargo elm build-set <Modules.toml> --config <.config> --target <三元组> --output <目录> [--features <列表>]",
            "按类似 Kconfig 的模块清单和配置，复用共享 framework 批量构建 ELM 模块。",
            &[
                ("<Modules.toml>", "模块声明、依赖和目标限制。"),
                (
                    "--config <.config>",
                    "由 configure-set 生成的 y/m/n 配置文件。",
                ),
                (
                    "--target <三元组>",
                    "必选目标：loongarch64-unknown-none 或 riscv64gc-unknown-none-elf。",
                ),
                ("--output <目录>", "模块 EKI/集成归档输出目录。"),
                ("--features <列表>", "可选的全局 Cargo feature 列表。"),
            ],
        ),
        Some("configure-set") => command_help(
            ui,
            "configure-set",
            "cargo elm configure-set <Modules.toml> --config <.config> --mode <模式>",
            "交互式或非交互式生成模块配置；结果只包含 y、m、n。",
            &[
                ("<Modules.toml>", "模块声明文件。"),
                ("--config <.config>", "配置输出路径。"),
                (
                    "--mode <模式>",
                    "必选值：config（逐项询问）、oldconfig（保留已有值并询问新增项）、defconfig（使用默认值）。",
                ),
            ],
        ),
        Some("inspect") => command_help(
            ui,
            "inspect",
            "cargo elm inspect <file.eki>",
            "以稳定的 key=value 格式输出 EKI header、block、ABI、import/export 和 mixin 信息。",
            &[("<file.eki>", "要检查的 EKI 或多变体 EKI 文件。")],
        ),
        Some("image-pack-metadata") => command_help(
            ui,
            "image-pack-metadata",
            "cargo elm image-pack-metadata <输出.eki> <名称> <版本> <类型> [--menu <标签> <描述> <路由>]",
            "仅根据 manifest 元数据生成最小 EKI；通常用于测试 fixture。",
            &[
                ("<输出.eki>", "生成的 metadata-only EKI 路径。"),
                ("<名称>", "写入 EKI manifest 的模块名称。"),
                ("<版本>", "写入 EKI manifest 的版本字符串。"),
                (
                    "<类型>",
                    "允许值：manager、service、driver、extension、filesystem、network、debug、other。",
                ),
                ("--menu ...", "可选菜单记录，必须同时提供标签、描述和路由。"),
            ],
        ),
        Some("image-pack-elf") => command_help(
            ui,
            "image-pack-elf",
            "cargo elm image-pack-elf <工程目录> <image.elf> <输出.eki>",
            "读取工程 Elm.toml 和 ELF/.elm.meta，完成段、重定位、ABI 和符号打包。",
            &[
                ("<工程目录>", "包含 Elm.toml 和接口包的工程目录。"),
                ("<image.elf>", "cargo build 生成的 PIE ELF。"),
                ("<输出.eki>", "生成的 EKI 路径。"),
            ],
        ),
        Some("image-bundle") => command_help(
            ui,
            "image-bundle",
            "cargo elm image-bundle <输出.eki> --variant <profile.manifest> <image.eki> <优先级> [...]",
            "把多个架构/Profile 变体组合成一个可选择的 EKI。`--variant` 可重复。",
            &[
                ("<输出.eki>", "多变体 EKI 输出路径。"),
                (
                    "--variant ...",
                    "Profile manifest、单变体 EKI 和无符号 u32 优先级三元组；目标必须匹配，组合键不能重复。",
                ),
            ],
        ),
        Some("image-hash") => command_help(
            ui,
            "image-hash",
            "cargo elm image-hash <输入.eki> <输出.eki>",
            "重新计算并写入 EKI header 的 SHA-256 image hash。",
            &[
                ("<输入.eki>", "原始 EKI。"),
                ("<输出.eki>", "更新 hash 后的 EKI。"),
            ],
        ),
        Some("image-keygen") => command_help(
            ui,
            "image-keygen",
            "cargo elm image-keygen <私钥种子> <公钥>",
            "从系统随机源生成 32 字节 Ed25519 私钥种子和对应公钥。",
            &[
                ("<私钥种子>", "输出的 32 字节私钥文件。"),
                ("<公钥>", "输出的 32 字节公钥文件。"),
            ],
        ),
        Some("image-sign") => command_help(
            ui,
            "image-sign",
            "cargo elm image-sign <输入.eki> <输出.eki> <私钥种子> <源标识> <epoch>",
            "使用 Ed25519 对 EKI 生成 proof block；输入必须已经包含 ABI fingerprint。",
            &[
                ("<输入.eki>", "待签名的 EKI；不会覆盖原文件。"),
                ("<输出.eki>", "写入签名 EKI 的路径。"),
                ("<私钥种子>", "32 字节 Ed25519 私钥种子文件。"),
                ("<源标识>", "非空、无 NUL 且不超过 128 字节的发布源标识。"),
                ("<epoch>", "非零十进制无符号发布 epoch。"),
            ],
        ),
        Some("image-verify") => command_help(
            ui,
            "image-verify",
            "cargo elm image-verify <file.eki>",
            "验证 image hash、proof、签名和 Rust ABI fingerprint。",
            &[("<file.eki>", "带签名的 EKI。")],
        ),
        Some("internal-fingerprint-header") => command_help(
            ui,
            "internal-fingerprint-header",
            "cargo elm internal-fingerprint-header <目标三元组> <输出.h>",
            "内部辅助命令：生成 ELM Rust ABI fingerprint C header。",
            &[
                (
                    "<目标三元组>",
                    "loongarch64-unknown-none 或 riscv64gc-unknown-none-elf。",
                ),
                ("<输出.h>", "写入 fingerprint 宏定义的 C header 路径。"),
            ],
        ),
        Some("help") => {
            global_help(ui);
            true
        }
        Some(other) => {
            global_help(ui);
            ui.warning(format!(
                "没有名为 {other:?} 的子命令；请使用 `cargo elm help` 查看列表"
            ));
            false
        }
    }
}

fn global_help(ui: &Ui) {
    ui.heading("cargo elm：ELM 工程、接口和镜像工具");
    println!("\n用法：");
    println!("  cargo elm [全局选项] <子命令> [参数]");
    ui.section("全局选项");
    ui.option("--color <模式>", "颜色输出：auto（默认）、always、never；也可由 CARGO_TERM_COLOR 设置。未设置终端颜色时遵循 NO_COLOR。");
    ui.option(
        "--no-color",
        "`--color never` 的快捷写法。覆盖终端自动颜色检测。",
    );
    ui.option(
        "-h, --help",
        "显示总览或指定子命令的详细帮助，例如 `cargo elm build --help`。",
    );
    ui.option("-V, --version", "显示 cargo-elm 版本。");
    ui.section("子命令");
    ui.command("new", "创建 ELM 工程骨架。");
    ui.command("sync", "同步 framework、接口包和源码投影。");
    ui.command("check", "检查工程与 Kernel API Profile 的兼容性。");
    ui.command("test", "运行工程开发侧测试。");
    ui.command("doctor", "诊断工程、接口和构建环境。");
    ui.command("profile-export", "从内核 ELF 导出 Kernel API Profile。");
    ui.command("symbol-probe", "生成内核符号探针 Rust 源码。");
    ui.command(
        "interface-schema",
        "从 EKI Profile 生成语言无关接口 schema。",
    );
    ui.command("descriptor", "生成通用 JSON descriptor 和 C header。");
    ui.command("sdk", "生成 Rust SDK 和资源句柄类型。");
    ui.command("bridge", "生成语言无关 Rust ELM bridge。");
    ui.command("package-check", "校验 LanguagePackage 与其接口/EKI 文件。");
    ui.command("build", "构建单个 ELM 并打包 EKI。");
    ui.command("build-set", "按 Modules.toml 批量构建模块。");
    ui.command("configure-set", "生成 y/m/n 模块配置。");
    ui.command("inspect", "读取 EKI 的结构化信息。");
    ui.command("image-pack-metadata", "生成 metadata-only EKI fixture。");
    ui.command("image-pack-elf", "把 PIE ELF 打包为 EKI。");
    ui.command("image-bundle", "组合多个 Profile/架构变体。");
    ui.command("image-hash", "重算 EKI image hash。");
    ui.command("image-keygen", "生成 Ed25519 密钥对。");
    ui.command("image-sign", "为 EKI 添加签名 proof。");
    ui.command("image-verify", "验证 EKI hash、ABI 和签名。");
    ui.command(
        "internal-fingerprint-header",
        "生成 ELM Rust ABI fingerprint C header（内部命令）。",
    );
    ui.command("help [子命令]", "显示本帮助或某个子命令的详细参数。");
    ui.note("提示：所有命令都支持 `--help`；build/check 使用 riscv64、loongarch64、all，profile-export/build-set 使用完整 Rust target triple。");
}

fn command_help(
    ui: &Ui,
    name: &str,
    usage: &str,
    description: &str,
    options: &[(&str, &str)],
) -> bool {
    ui.heading(format!("cargo elm {name}"));
    println!("\n用法：\n  {usage}\n\n{description}");
    ui.section("参数和选项");
    for (syntax, description) in options {
        ui.option(syntax, description);
    }
    ui.option("-h, --help", "显示此帮助。");
    ui.option("--color <模式>", "覆盖全局颜色模式：auto、always、never。");
    ui.option("--no-color", "关闭颜色输出。");
    true
}
