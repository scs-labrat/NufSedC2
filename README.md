# NufSed C2

A next-generation, Python-based Command & Control (C2) framework equipped with chaos-key encryption, dynamic port assignment, and cross-platform payload generation. **NufSed C2** is designed to simplify red team operations while increasing stealth and flexibility across multiple target platforms.

---

## Key Features

### Chaos-Key Encryption
- **Time-Sensitive Keys:**  
  Dynamically generates encryption keys based on a shared secret and the current hour, complicating traffic analysis.
- **Stealth and Security:**  
  Obfuscates communications between the C2 server and implants, making traditional static XOR keys obsolete.

### Dynamic Port Assignment
- **Unique Per-Agent Ports:**  
  Each new implant receives a randomly assigned port, improving both traffic compartmentalization and stealth.
- **Improved Scalability:**  
  Seamlessly manage multiple implants without bottlenecking on a single known port.

### Cross-Platform Payloads
- **Windows:**  
  Generate Python-based backdoors or .exe files (via PyInstaller).
- **Linux:**  
  Deploy Python or shell script implants, with simple persistence (e.g., cron).
- **Android (Linux Host Required):**  
  Build APK implants using Buildozer, expanding operations into mobile realms.

### Persistence & Self-Deletion
- **Persistence Options:**  
  - **Windows:** Modify registry keys for autorun.  
  - **Linux:** Add cron jobs for stealthy relaunches.  
  - **Android:** Integrate into Termux startup scripts.
- **Self-Deletion (Kill Command):**  
  Implants can remove themselves upon receiving a kill command, ensuring minimal forensic trace.

---

## Requirements

- **Python 3.6+**
- **PyInstaller (for Windows payloads)**
- **Buildozer & Android SDK/NDK (for Android APKs, on Linux hosts)**
- **Colorama, PrettyTable, and Other Python Dependencies:**  
  Install from `requirements.txt`.

---

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/scs-labrat/nufsedc2.git
   cd nufsedc2
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   
3. **Run the C2 Server:**
   ```bash
   python3 nufsedc2.py
   ```
   
   Upon running, the C2 generates or loads a shared secret and launches a primary listener.

---

## Usage

- **Help Menu:**
  ```bash
  Command#> help
  ```
  
- **Start a Listener:**
  ```bash
  Command#> listeners -g
  ```
  (Follow prompts to specify IP, port, and protocol.)

- **List Sessions:**
  ```bash
  Command#> sessions -l
  ```

- **Interact with a Session:**
  ```bash
  Command#> sessions -i <session_id>
  ```

- **Generate Payloads (Examples):**
  ```bash
  # Windows EXE Payload
  Command#> winplant exe

  # Linux SH Payload
  Command#> linplant sh
  
  # Android APK (on Linux)
  Command#> androidplant apk
  ```

- **Kill All Implants:**
  ```bash
  Command#> kill
  ```

- **Exit C2:**
  ```bash
  Command#> exit
  ```

---

## Download

**Latest Release:**  
[Download the latest release](https://github.com/scs-labrat/nufsedc2/releases/latest)

Here you can find pre-compiled binaries or source archives for convenience.

---

## Contributing

Contributions are welcome!  
- Submit issues or pull requests for bug fixes, enhancements, or new features.
- Improve documentation and help extend compatibility.

---

## Disclaimer

**For educational and authorized security testing purposes only.**  
Misuse of this tool can lead to severe legal consequences. The authors disclaim any responsibility for unauthorized or malicious use. Always ensure you have proper authorization before using NufSed C2 on any target systems.

