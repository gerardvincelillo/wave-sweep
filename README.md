# WaveSweep - Offline Wireless Security Auditor

```
__        __              ____                         
\ \      / /_ ___   _____/ ___|_      _____  ___ _ __  
 \ \ /\ / / _` \ \ / / _ \___ \ \ /\ / / _ \/ _ \ '_ \ 
  \ V  V / (_| |\ V /  __/___) \ V  V /  __/  __/ |_) |
   \_/\_/ \__,_| \_/ \___|____/ \_/\_/ \___|\___| .__/ 
                                                |_|    
``` 

WaveSweep is a Python-based wireless security auditing tool that operates 100% offline. Designed for security professionals, security engineers, and network administrators, it provides comprehensive wireless network analysis and reporting without cloud dependencies.


---

## Features

- **AP Discovery**: Detects nearby access points and client devices
- **Vulnerability Scanning**: Identifies weak protocols (WEP, WPS) and misconfigurations
- **Rogue AP Detection**: Compares against a trusted baseline to identify unauthorized devices
- **Signal Mapping**: Visualizes signal strength and vulnerability distribution (Linux only)
- **Offline Operation**: No internet connection required
- **Automated Reporting**: Generates text or HTML reports with security findings
- **Cross-Platform**: Works on Linux (full features) and Windows (limited to connected AP info)

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/gerardvincelillo/wave-sweep.git
    cd wave-sweep
    ```

2. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3. **(Linux only) Put your wireless interface in monitor mode:**
    ```bash
    sudo airmon-ng start wlan0
    ```

    > **Note:** On Windows, monitor mode is rarely supported. You can still audit your currently connected Wi-Fi network.

---

## Usage

```bash
# Linux (recommended for full features)
sudo python wavesweep.py [options]

# Windows (limited: only info about connected Wi-Fi)
python wavesweep.py [options]
```

### Options:
- `-i INTERFACE` : Wireless interface (default: wlan0mon on Linux, Wi-Fi on Windows)
- `-d DURATION`  : Scan duration in seconds (default: 30)
- `-r {text,html,json}` : Report format (default: text)
- `-v`           : Generate network visualization (Linux only)
- `-u`           : Update AP baseline with current scan
- `--input-scan <file>` : Analyze pre-captured AP JSON data instead of live sniffing

### Example:
```bash
sudo python wavesweep.py -i wlan0mon -d 45 -r html -v -u
```

Offline replay mode (no live capture required):
```bash
python wavesweep.py --input-scan samples/scan.json -r json
```

---

## Project Structure

```
wavesweep/
├── wavesweep.py             # Main executable
├── wavesweep_baseline.json  # Trusted AP database
├── requirements.txt         # Python dependencies
├── docs/
│   └── README.md            # Project documentation
├── .gitignore               # Version control ignore rules
└── reports/                 # Generated reports
```

---

## Platform Support & Limitations

- **Linux:** Full feature set, including monitor mode scanning, AP/client discovery, and visualization.
- **Windows:** Only information about the currently connected Wi-Fi network is available. Most Wi-Fi cards do not support monitor mode on Windows.

---

## About

Created by a security engineer to learn, share, and demonstrate practical Python and cybersecurity skills.  
Feel free to use, contribute, or fork for your own learning!

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License.

**Author:** geddzzy 

**Copyright ©** 2025 geddzzy

All rights reserved.

## Docs

- `docs/README.md`: docs index for the repository
- `docs/implementation_checklist.md`
- `docs/project_vision.md`
- `docs/stack_inventory.md`
