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
```

2. **Install dependencies**
```bash
pip install fastapi uvicorn pydantic
```

3. **Create data directory**
```bash
sudo mkdir -p /home/data/share/txt
sudo chown $USER:$USER /home/data/share/txt
```

4. **Run the application**
```bash
python3 app.py
```

5. **Access the web interface**
```
http://localhost:3069
```

## ⚙️ Configuration

### Directory Structure
```
/home/data/share/txt/          # Base directory for list files
├── domains.txt                # Your list files
├── ips.txt
├── urls.txt
├── change.log                 # Automatic change log
└── *.txt.bak.YYYYMMDDHHMMSS  # Automatic backups
```

### Configuration Variables

Edit `app.py` to customize:

```python
BASE_DIR = Path("/home/data/share/txt")  # Data directory
CHANGE_LOG = BASE_DIR / "change.log"     # Change log location
PORT = 3069                               # Web server port
```

## 🖥️ Usage

### Web Interface

1. **Select a file** from the left sidebar
2. **Add entries** using the input field at the top
3. **Edit entries** by clicking the "Edit" button
4. **Delete entries** by clicking the "Delete" button (with confirmation)
5. **Search/filter** entries using the search box
6. **Copy export URL** to use with FortiGate

### FortiGate Integration

Use the export endpoint in your FortiGate External Connector configuration:

```
http://your-server:3069/export/filename.txt
```

This returns raw plain-text content that FortiGate can consume.

## 🔌 API Endpoints

### File Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/files` | List all .txt files |
| `GET` | `/api/files/{filename}` | Get all entries in a file |
| `POST` | `/api/files/{filename}` | Add new entry |
| `PUT` | `/api/files/{filename}/{index}` | Update entry at index |
| `DELETE` | `/api/files/{filename}/{index}` | Delete entry at index |

### Export

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/export/{filename}` | Get raw file content (for FortiGate) |

### API Examples

**List all files:**
```bash
curl http://localhost:3069/api/files
```

**Get file entries:**
```bash
curl http://localhost:3069/api/files/domains.txt
```

**Add entry:**
```bash
curl -X POST http://localhost:3069/api/files/domains.txt \
  -H "Content-Type: application/json" \
  -d '{"value":"example.com"}'
```

**Update entry:**
```bash
curl -X PUT http://localhost:3069/api/files/domains.txt/0 \
  -H "Content-Type: application/json" \
  -d '{"value":"newexample.com"}'
```

**Delete entry:**
```bash
curl -X DELETE http://localhost:3069/api/files/domains.txt/0
```

**Export for FortiGate:**
```bash
curl http://localhost:3069/export/domains.txt
```

## 🏭 Production Deployment

### Systemd Service

Create `/etc/systemd/system/fglistmanager.service`:

```ini
[Unit]
Description=FortiGate List Manager
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/home/py/webdavfqdn
ExecStart=/usr/bin/python3 /home/py/webdavfqdn/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable fglistmanager
sudo systemctl start fglistmanager
sudo systemctl status fglistmanager
```

### Nginx Reverse Proxy

Create `/etc/nginx/sites-available/fglistmanager`:

```nginx
server {
    listen 80;
    server_name listmanager.example.com;

    location / {
        proxy_pass http://127.0.0.1:3069;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
    }
}
```

**Enable:**
```bash
sudo ln -s /etc/nginx/sites-available/fglistmanager /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### SSL with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d listmanager.example.com
```

## 🔒 Security Considerations

- ✅ **Path Traversal Protection**: Validates filenames to prevent directory traversal attacks
- ✅ **Input Validation**: Sanitizes all user inputs
- ✅ **Filename Restrictions**: Only allows `.txt` files with safe characters
- ✅ **No Root Execution**: Application refuses to run as root
- ⚠️ **Authentication**: Consider adding authentication (Basic Auth via Nginx or implement in app)
- ⚠️ **HTTPS**: Always use HTTPS in production (via Nginx + Let's Encrypt)
- ⚠️ **Firewall**: Restrict access to trusted IPs if possible

## 📊 Features in Detail

### File Locking
Thread-safe file operations prevent corruption when multiple users edit simultaneously.

### Automatic Backups
Before any modification, a timestamped backup is created:
```
domains.txt.bak.20260118143022
```

### Change Logging
All operations are logged to `change.log`:
```
[2026-01-18 14:30:22] [domains.txt] [ADD] [example.com]
[2026-01-18 14:31:15] [domains.txt] [UPDATE] [example.com -> test.com]
[2026-01-18 14:32:08] [domains.txt] [DELETE] [test.com]
```

### Duplicate Prevention
The application prevents duplicate entries within the same file.

## 🎨 User Interface

- **Dark Mode**: Modern, eye-friendly dark theme
- **Responsive**: Works on desktop, tablet, and mobile
- **Real-time Stats**: Shows total files and entries
- **File Type Icons**: Visual indicators for different list types (IP, domain, URL, etc.)
- **Toast Notifications**: Instant feedback for all operations
- **Keyboard Shortcuts**: 
  - `Enter` to save when editing
  - `Escape` to cancel
  - `Enter` in add field to add entry

## 🐛 Troubleshooting

### Permission Denied
```bash
sudo chown -R www-data:www-data /home/data/share/txt
sudo chmod -R 755 /home/data/share/txt
```

### Port Already in Use
Change `PORT` in `app.py` or kill the process:
```bash
sudo lsof -i :3069
sudo kill -9 <PID>
```

### Service Won't Start
Check logs:
```bash
sudo journalctl -u fglistmanager -f
```

## 📝 License

MIT License - feel free to use this project for personal or commercial purposes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues and questions, please open an issue on GitHub.

---

**Made with ❤️ for network administrators and security professionals**