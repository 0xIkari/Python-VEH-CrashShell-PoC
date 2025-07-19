# CrashShell: A Crash-Triggered Memory Exfil and Shell Proof-of-Concept

> **DISCLAIMER**: This is a proof-of-concept (PoC) for research purposes only. It demonstrates what is possible using Python's `ctypes` and Windows Vectored Exception Handling (VEH). This PoC should **not be used in production** or for malicious purposes. You've been warned.

## Overview

**CrashShell** is a Python-based, stdlib-only PoC that explores the use of Windows VEH (Vectored Exception Handler) to intercept memory access violations and turn them into post-crash memory exfiltration and reverse shell triggers.

This project began as a secure memory manager with tamper-aware wiping, but evolved into an exploration of what can be done *between a crash and Windows exception handling*. The result is a **crash-triggered, memory-resident, page-protected reverse shell launcher** written entirely in Python.

## Showcase

![Recording 2025-07-19 043717](https://github.com/user-attachments/assets/aa466bf5-310e-423f-b22a-6ae98d6d327b)

---

## Key Features

- **Pure Python (stdlib-only)**
- **Page-protected secure memory using `VirtualAlloc`, `VirtualProtect`, `VirtualLock`**
- **Manual region registration for fault-based wipe control**
- **VEH hook to intercept `EXCEPTION_ACCESS_VIOLATION`**
- **Crash-triggered reverse socket connection**
- **Optional command loop with WinAPI command execution and output return**
- **Wipes memory after command execution**
- **No shellcode, no dropped files, no static signature**
- **No Event 1000 crash log or WER dump**

---

## Use Cases

- Demonstration of novel runtime execution during crash window
- Post-crash anti-forensics with secure memory cleanup
- Research into memory control primitives and low-level Windows exception handling in Python
- Educational exploration of what not to allow in high-trust runtimes

---

## What This Is Not

- This is **not** malware.
- This is **not** production-grade code.
- This is **not** designed to evade modern EDR in operational environments.
- This is **not** persistent, and **does not survive reboot**.

---

## How It Works

1. Allocates and page-protects memory region using WinAPI
2. Registers that region for secure handling
3. Installs a Vectored Exception Handler (VEH) that:
   - Detects access violation into protected memory
   - Opens a reverse socket
   - Optionally receives a command, executes it, and returns output
   - Wipes the memory in multiple passes (e.g., 0xAA, 0x55, 0x00)
   - Terminates the process cleanly

---

## Security Implications

CrashShell demonstrates that:
- VEH can be hijacked in Python with no visibility
- You can execute post-crash logic before the OS gets control
- Page-protected memory can act as a trapdoor trigger
- Secure memory routines must account for fault-path logic
- Memory exfil can be hidden behind intentional crash behavior

## Want SecureMemory?

> https://github.com/nuclear-treestump/EEEE Work In Progress

---

## Legal and Ethical Use

CrashShell is provided under the terms of the MIT License for **research and educational purposes only**. Any use of this tool to compromise, access, or exfiltrate data from systems you do not own or have explicit authorization for is **strictly prohibited**.

If you think this is cool, please star and provide credit if used elsewhere.

If you are a defender, researcher, or vendor and you want to better understand how VEH and memory trap-based logic can be abused: this PoC is for you.

If you are not? You shouldn't be here.

---

## Credit

Created by **0xIkari** (that's me), 2025

This is believed to be the **first working example of a crash-triggered memory exfil + shell system implemented in Python using stdlib and VEH**.

---

> "I just wanted secure memory handling that wiped on tamper. Now I have a ghost that lives in the space between crash and cleanup."

