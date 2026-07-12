# EnPortv-Killer
- PoC for vulnerability in EnPortv driver from EnCase

- As of 2026-07-10, the driver is **listed on [LOLDDrivers](https://www.loldrivers.io/)** but remains **absent** from [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) as of 2026-07-10

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `EnPortv.sys` SHA256: `d42f1b420747b82533e33107c710c45c29ff20aa5da3d1c8498b7bed7f9ebc81`

## Usage

Place `EnPortv.sys` in the same directory as the executable.

```text
PS C:\Users\User\Desktop> .\EnPortv-Killer.exe -h
BYOVD process killer using ardrv driver

Usage: EnPortv-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p EnPortv-Killer

# Run
.\EnPortv-Killer.exe -n notepad.exe
```
