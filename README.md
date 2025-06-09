# 🛡️ Windows Security Projects  by Om Dattatray Shimpi

Welcome to my collection of Windows-based system and security tools. Each project dives deep into OS internals, API hooking, process manipulation, and binary parsing—covering both offensive and defensive security concepts.

---

## 🧠 Projects Overview

| Project Name             | Description                                                   | Technologies             |
|--------------------------|---------------------------------------------------------------|---------------------------|
| 🛑 Sentinel              | Blocks unauthorized process creation using API hooking         | C++, Windows API, MinHook |
| 🔐 Ozone (DLP System)    | Prevents sensitive data leaks by controlling clipboard access  | C++, MinHook, API Hooking |
| 🚨 Privilege Escalation | Gains elevated rights using access token manipulation          | C++, Windows API, Tokens  |
| 📦 PE File Parser        | Parses internal structure of PE files like Notepad.exe         | C++, Windows Structs      |

---

## 🛑 Sentinel – Process Creation Blocker

**Goal:** Prevent the execution of blacklisted processes at the system level.

### 🔧 Features:
- Hooks `CreateProcessW` using `SetWindowsHookEx`.
- Maintains a dynamic **allowlist/denylist** via configuration.
- Blocks non-whitelisted EXEs from launching.

### 💻 Tech Stack:
- C++
- Windows Hooks (`WH_CBT`)
- Custom DLL Injector
- MinHook Library

### 📸 Example:
``Process creation blocked: chrome.exe (Not in allowlist)``

---

## 🔐 Ozone – Windows Data Loss Prevention (DLP)

**Goal:** Prevent data leaks by controlling **Copy, Paste, Download, Print, and Share** in applications like Notepad.

### 🔧 Features:
- API Hooking for clipboard functions (`OpenClipboard`, `GetClipboardData`).
- Dynamically configurable rules via JSON.
- Real-time blocking of Paste/Cut operations based on flags.

### 📦 Current Scope:
- Targets **Notepad.exe** for clipboard operations.
- Web dashboard planned for centralized policy control.

### ⚙️ Libraries Used:
- C++, MinHook, Windows Native API

---

## 🚨 Privilege Escalation – Access Token Manipulation

**Goal:** Gain **SYSTEM-level** privileges from a standard user context by duplicating process tokens.

### 🕵️‍♂️ Method:
- Identifies high-privilege process (e.g., `winlogon.exe`)
- Uses `OpenProcessToken` + `DuplicateTokenEx`
- Executes new process with SYSTEM rights using `CreateProcessWithTokenW`

### 🔒 Real-World Relevance:
- Based on techniques used in attacks like **JuicyPotato** and **RoguePotato**
- Demonstrates Windows token architecture and impersonation flaws

### 🔧 APIs Used:
- `OpenProcess()`
- `OpenProcessToken()`
- `DuplicateTokenEx()`
- `CreateProcessWithTokenW()`

---

## 📦 PE File Parser – Portable Executable Format Analyzer

**Goal:** Reverse engineer and statically analyze Windows `.exe` files.

### 🧬 Parsed Structures:
- `IMAGE_DOS_HEADER`
- `IMAGE_NT_HEADERS`
- `IMAGE_FILE_HEADER`
- `IMAGE_OPTIONAL_HEADER`
- `IMAGE_SECTION_HEADER`
- Import and Export Tables

### 🔍 Use Cases:
- Malware Analysis
- Binary Reverse Engineering
- Static Code Inspection

### 🛠 Output:
- Entry Point
- Section Table
- DLL Imports and Functions
- File Alignment, RVA ↔ VA Mapping

---

## 🧠 Key Skills Demonstrated

✅ Windows Internals  
✅ API Hooking & DLL Injection  
✅ Access Token Privileges  
✅ PE File Format  
✅ C++ System Programming  
✅ Security Research & Red Team Tactics

---

## 📌 Author

**Om Dattatray Shimpi**  
🖥️ TE-IT Student  
🎓 Passionate about OS internals, Cybersecurity, and Windows System Programming 
📫 Connect: [LinkedIn]((https://www.linkedin.com/in/om-shimpi-239838251/)) 

---

## 🔗 Want More?

💬 DM for:
- Collaboration on Security Tools  
- Resume-friendly walkthroughs  
- Full video demos of each project  
- GitHub project structure and code

---

> 💡 *"Understanding internals isn't optional if you want to secure the system from the inside."*

