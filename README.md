# FortiGate List Manager

A lightweight, modern web application for managing plain-text list files used by FortiGate Firewall External Connectors. Built with FastAPI and vanilla JavaScript, featuring a sleek dark-mode UI for easy management of IPs, domains, URLs, and other security lists.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.68+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🌟 Features

- **📁 Multi-File Management**: Manage multiple `.txt` list files from a centralized interface
- **✏️ CRUD Operations**: Create, read, update, and delete entries with ease
- **🔍 Real-time Search**: Filter files and entries instantly
- **🔒 Thread-Safe**: File locking prevents data corruption during concurrent access
- **📝 Change Logging**: All modifications are logged with timestamps
- **💾 Automatic Backups**: Creates timestamped backups before any modification
- **🔗 Export Endpoint**: Direct plain-text export for FortiGate External Connectors
- **🎨 Modern UI**: Clean, responsive dark-mode interface
- **⚡ Lightweight**: No database required, works directly with text files
- **🛡️ Security**: Path traversal protection and input validation

## 📋 Requirements

- Python 3.7+
- FastAPI
- Uvicorn
- Pydantic

## 🚀 Quick Start

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/noahdaniel163/webdavfqdn.git
cd webdavfqdn
