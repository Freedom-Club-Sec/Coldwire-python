# Coldwire - The Ultra‑Paranoid Post‑Quantum Messenger
![Tests](https://github.com/Freedom-Club-Sec/Coldwire/actions/workflows/tests.yml/badge.svg)  ![Coverage](https://coveralls.io/repos/github/Freedom-Club-Sec/Coldwire/badge.svg?branch=main) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/1c34011b18284a3cb349ffe5415eea53)](https://app.codacy.com/gh/Freedom-Club-Sec/Coldwire/dashboard)

---
**Coldwire** is designed to survive *the worst attacks* and when operated correctly it offers significantly better security than any messenger currently available.

## 🔒 Security Model & Features
- **Best‑case security**: achieves [unbreakable encryption](https://en.wikipedia.org/wiki/One-time_pad) under the principles of information theory using [one‑time pads](https://en.wikipedia.org/wiki/One-time_pad) 
- **Worst‑case security**: falls back only to combined security of ML‑KEM‑1024 and McEliece8192128  
- **Perfect-Forward-Secrecy**: on every [OTP](https://en.wikipedia.org/wiki/One-time_pad) batch through ephemeral PQC key exchanges  
- **Plausible Deniability**: messages are not cryptographically tied to you, providing more deniability than [Off‑The‑Record messaging](https://en.wikipedia.org/wiki/Off-the-record_messaging) !
- **Mandatory SMP**: We enforce [Socialist millionaire problem](https://en.wikipedia.org/wiki/Socialist_millionaire_problem) before any chat. **MiTM attacks are impossible**.  
- **Minimal Attack Surface**:  
  - Tkinter UI only, no embedded browsers or HTML
  - Minimal Python dependecies
  - All untrusted inputs truncated to safe lengths to prevent buffer‑overflow in liboqs or Tk  
- **Traffic obfuscation**: Network adversaries (ISP, etc) cannot easily censorship Coldwire, because we utilize HTTP(s).
- **Metadata‑Free**: Random 16‑digit session IDs, no server contacts, no logs, no server‑side metadata, enforced passwordless authentication. Everything is local, encrypted, and ephemeral.

## ⚠️ Disclaimer
While Coldwire enforces paranoid‑level security features, the [protocol](https://github.com/Freedom-Club-Sec/Coldwire/blob/main/PROTOCOL.md), and codebase are under active development. 

**Do not** use for production‑grade secrecy until an formal audit is complete.

## Installation
### Dependecies
- liboqs-python
- git
- CMake
- C compiler
- Python 3
  
Install [liboqs-python](https://github.com/open-quantum-safe/liboqs-python/) by running:
```sh
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
```

Clone Coldwire repositioary and install `requirements.txt` by running:
```
git clone https://github.com/Freedom-Club-Sec/Coldwire
cd Coldwire
pip install -r requirements.txt
```

## Usage
Run Coldwire's GUI using:
```sh
python3 main.py
```
