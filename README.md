# Coldwire — The Ultra‑Paranoid Post‑Quantum Messenger
![Tests](https://github.com/Freedom-Club-FC/Coldwire/actions/workflows/tests.yml/badge.svg)  ![Coverage](https://coveralls.io/repos/github/Freedom-Club-FC/Coldwire/badge.svg?branch=main)  [![Codacy Badge](https://app.codacy.com/project/badge/Grade/3f378d152ff24f2f93c9d93928f91ee2)](https://app.codacy.com/gh/Freedom-Club-FC/Coldwire/dashboard)

---
**Coldwire** is designed to survive *the worst attacks* and when operated correctly it offers significantly better security than any messenger currently available.

## 🔒 Security Model & 🌟 Key Features
- **Best‑case security**: achieves [unbreakable encryption](https://en.wikipedia.org/wiki/One-time_pad) under the principles of information theory using [one‑time pads](https://en.wikipedia.org/wiki/One-time_pad) 
- **Worst‑case security**: falls back only to ML‑KEM‑1024 (Kyber) resistance  
- **Perfect-Forward-Secrecy**: on every [OTP](https://en.wikipedia.org/wiki/One-time_pad) batch through ephemeral PQC key exchanges  
- **Plausible Deniability**: messages are not cryptographically tied to you, proving more deniability than [Off‑The‑Record messaging](https://en.wikipedia.org/wiki/Off-the-record_messaging) !
- **Mandatory SMP**: We enforce [Socialist millionaire problem](https://en.wikipedia.org/wiki/Socialist_millionaire_problem) before any chat. **MiTM attacks are impossible**.  
- **NIST PQC Tier‑5**: We use highest security algorithms (Kyber1024, Dilithium5) that provide AES‑256 strength using [OQS Project](https://openquantumsafe.org/)
- **Minimal Attack Surface**:  
  - Tkinter UI only, no embedded browsers or HTML
  - Minimal Python dependecies
  - All untrusted inputs truncated to safe lengths to prevent buffer‑overflow in liboqs or Tk  
- **Metadata‑Free**: Random 16‑digit session IDs, no server contacts, no logs, no server‑side metadata, enforced passwordless authentication. Everything is local, encrypted, and ephemeral.

