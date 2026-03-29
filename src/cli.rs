use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "mapeced")]
#[command(about = "MAP-E daemon", long_about = None)]
#[command(version)]
pub struct Cli {
    /// 設定ファイルのパス
    #[arg(short, long, default_value = "/etc/mapeced/config.toml")]
    pub config: PathBuf,

    /// ログレベル (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    pub log_level: String,
}
