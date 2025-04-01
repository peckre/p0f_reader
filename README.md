```
# Hexdump and Tcpdump to p0f Analyzer

This Python tool allows you to convert either a **hexdump** or a **tcpdump summary line** into a valid `.pcap` file, then analyze it using **p0f** for passive OS fingerprinting.

## 🔧 Features

- Accepts raw hexdumps (e.g. from `xxd`) and reconstructs packets
- Accepts tcpdump-style summary lines (e.g. SYN packets with MSS)
- Converts to `.pcap` and runs `p0f` on it automatically
- Cleans up temporary files after analysis

## 🚀 Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
  ```bash
  pip install scapy
  ```
- `p0f` installed and accessible via `sudo`
  ```bash
  sudo apt install p0f
  ```

## 🖥️ Usage

```bash
python3 hexdump_to_p0f.py
```

Then follow the prompt to choose between:

1. **Hexdump**: Paste your packet bytes in hex format.
2. **tcpdump line**: Paste a single summary line.

## 📂 Output

- A temporary `.pcap` file is created
- `p0f` is run on that file and results are printed
- File is deleted after processing
  
```
