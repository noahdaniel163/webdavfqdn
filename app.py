#!/usr/bin/env python3
"""
FortiGate External Connector List Manager
A lightweight web application to manage plain-text list files for FortiGate Firewall External Connectors.

================================================================================
SYSTEMD SERVICE EXAMPLE (/etc/systemd/system/fglistmanager.service):
================================================================================
# [Unit]
# Description=FortiGate List Manager
# After=network.target
#
# [Service]
# Type=simple
# User=www-data
# Group=www-data
# WorkingDirectory=/home/py/webdavfqdn
# ExecStart=/usr/bin/python3 /home/py/webdavfqdn/app.py
# Restart=always
# RestartSec=5
# Environment=PYTHONUNBUFFERED=1
#
# [Install]
# WantedBy=multi-user.target
#
# Commands:
# sudo systemctl daemon-reload
# sudo systemctl enable fglistmanager
# sudo systemctl start fglistmanager
# sudo systemctl status fglistmanager

================================================================================
NGINX REVERSE PROXY EXAMPLE (/etc/nginx/sites-available/fglistmanager):
================================================================================
# server {
#     listen 80;
#     server_name listmanager.example.com;
#
#     location / {
#         proxy_pass http://127.0.0.1:3069;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header X-Forwarded-Proto $scheme;
#         proxy_read_timeout 300;
#         proxy_connect_timeout 300;
#     }
# }
#
# Commands:
# sudo ln -s /etc/nginx/sites-available/fglistmanager /etc/nginx/sites-enabled/
# sudo nginx -t
# sudo systemctl reload nginx
"""

import os
import re
import fcntl
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
import uvicorn

# ==============================================================================
# CONFIGURATION
# ==============================================================================

BASE_DIR = Path("/home/data/share/txt")
CHANGE_LOG = BASE_DIR / "change.log"
PORT = 3069

# ==============================================================================
# FASTAPI APP INITIALIZATION
# ==============================================================================

app = FastAPI(title="FortiGate List Manager", docs_url=None, redoc_url=None)

# ==============================================================================
# PYDANTIC MODELS
# ==============================================================================

class EntryValue(BaseModel):
    value: str

# ==============================================================================
# FILE LOCKING CONTEXT MANAGER
# ==============================================================================

# Global lock dictionary for thread-safe file access
import threading
_file_locks = {}
_lock_mutex = threading.Lock()

def get_file_lock(filepath: Path) -> threading.Lock:
    """Get or create a lock for a specific file."""
    with _lock_mutex:
        key = str(filepath.resolve())
        if key not in _file_locks:
            _file_locks[key] = threading.Lock()
        return _file_locks[key]

@contextmanager
def file_lock(filepath: Path, mode: str = 'r'):
    """Thread-safe file access with locking."""
    lock = get_file_lock(filepath)
    lock.acquire()
    try:
        if 'r' in mode and filepath.exists():
            with open(filepath, mode, encoding='utf-8') as f:
                yield f
        elif 'w' in mode or 'a' in mode:
            with open(filepath, mode, encoding='utf-8') as f:
                yield f
        else:
            yield None
    finally:
        lock.release()

# ==============================================================================
# SECURITY & VALIDATION HELPERS
# ==============================================================================

def validate_filename(filename: str) -> Path:
    """Validate filename and prevent path traversal attacks."""
    # Must end with .txt
    if not filename.endswith('.txt'):
        raise HTTPException(status_code=400, detail="Only .txt files are allowed")
    
    # Prevent path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Sanitize filename
    if not re.match(r'^[a-zA-Z0-9_\-\.]+\.txt$', filename):
        raise HTTPException(status_code=400, detail="Invalid filename characters")
    
    filepath = BASE_DIR / filename
    
    # Double-check resolved path is within BASE_DIR
    try:
        filepath.resolve().relative_to(BASE_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    return filepath

def validate_entry(filename: str, value: str) -> str:
    """Validate entry - just trim whitespace and check not empty."""
    value = value.strip()
    
    if not value:
        raise HTTPException(status_code=400, detail="Empty entries are not allowed")
    
    return value

# ==============================================================================
# BACKUP & LOGGING
# ==============================================================================

def create_backup(filepath: Path):
    """Create timestamped backup before modification."""
    if filepath.exists():
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        backup_path = filepath.with_suffix(f'.txt.bak.{timestamp}')
        with file_lock(filepath, 'r') as src:
            if src:
                content = src.read()
                with open(backup_path, 'w', encoding='utf-8') as dst:
                    dst.write(content)

def log_change(filename: str, action: str, old_value: str = "", new_value: str = ""):
    """Log all changes to change.log."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if old_value and new_value:
        log_entry = f"[{timestamp}] [{filename}] [{action}] [{old_value} -> {new_value}]\n"
    elif old_value:
        log_entry = f"[{timestamp}] [{filename}] [{action}] [{old_value}]\n"
    elif new_value:
        log_entry = f"[{timestamp}] [{filename}] [{action}] [{new_value}]\n"
    else:
        log_entry = f"[{timestamp}] [{filename}] [{action}]\n"
    
    # Ensure base directory exists
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(CHANGE_LOG, 'a', encoding='utf-8') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(log_entry)
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

# ==============================================================================
# FILE OPERATIONS
# ==============================================================================

def read_file_lines(filepath: Path) -> list:
    """Read file and return list of lines (excluding empty lines)."""
    if not filepath.exists():
        return []
    with file_lock(filepath, 'r') as f:
        if f:
            # Filter out empty lines
            return [line.rstrip('\n\r') for line in f.readlines() if line.strip()]
    return []

def write_file_lines(filepath: Path, lines: list):
    """Write lines to file."""
    # Ensure base directory exists
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with file_lock(filepath, 'w') as f:
        if f:
            f.write('\n'.join(lines))
            if lines:  # Add trailing newline if file has content
                f.write('\n')

# ==============================================================================
# API ENDPOINTS
# ==============================================================================

@app.get("/api/files")
def list_files():
    """List all available .txt files."""
    if not BASE_DIR.exists():
        return {"files": []}
    
    files = []
    for f in sorted(BASE_DIR.glob("*.txt")):
        # Exclude backup files and log files
        if not f.name.endswith('.lock') and '.bak.' not in f.name and f.name != 'change.log':
            files.append(f.name)
    
    return {"files": files}

@app.get("/api/files/{filename}")
def get_file_entries(filename: str):
    """Return file entries with line index."""
    filepath = validate_filename(filename)
    
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    lines = read_file_lines(filepath)
    entries = [{"index": i, "value": line} for i, line in enumerate(lines)]
    
    return {"filename": filename, "entries": entries, "count": len(entries)}

@app.post("/api/files/{filename}")
def add_entry(filename: str, entry: EntryValue):
    """Append new entry to file."""
    filepath = validate_filename(filename)
    value = validate_entry(filename, entry.value)
    
    # Create backup before modification
    create_backup(filepath)
    
    # Read existing lines
    lines = read_file_lines(filepath)
    
    # Check for duplicates
    if value in lines:
        raise HTTPException(status_code=400, detail="Entry already exists")
    
    # Append new entry
    lines.append(value)
    write_file_lines(filepath, lines)
    
    # Log the change
    log_change(filename, "ADD", new_value=value)
    
    return {"success": True, "index": len(lines) - 1, "value": value}

@app.put("/api/files/{filename}/{index}")
def update_entry(filename: str, index: int, entry: EntryValue):
    """Update entry at specific line index."""
    filepath = validate_filename(filename)
    
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    value = validate_entry(filename, entry.value)
    
    # Create backup before modification
    create_backup(filepath)
    
    lines = read_file_lines(filepath)
    
    if index < 0 or index >= len(lines):
        raise HTTPException(status_code=400, detail="Invalid line index")
    
    old_value = lines[index]
    
    # Check for duplicates (excluding current line)
    if value in lines and lines.index(value) != index:
        raise HTTPException(status_code=400, detail="Entry already exists")
    
    lines[index] = value
    write_file_lines(filepath, lines)
    
    # Log the change
    log_change(filename, "UPDATE", old_value=old_value, new_value=value)
    
    return {"success": True, "index": index, "old_value": old_value, "new_value": value}

@app.delete("/api/files/{filename}/{index}")
def delete_entry(filename: str, index: int):
    """Delete entry at specific line index."""
    filepath = validate_filename(filename)
    
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    # Create backup before modification
    create_backup(filepath)
    
    lines = read_file_lines(filepath)
    
    if index < 0 or index >= len(lines):
        raise HTTPException(status_code=400, detail="Invalid line index")
    
    deleted_value = lines.pop(index)
    write_file_lines(filepath, lines)
    
    # Log the change
    log_change(filename, "DELETE", old_value=deleted_value)
    
    return {"success": True, "deleted_value": deleted_value}

@app.get("/export/{filename}")
def export_file(filename: str):
    """Return RAW file content for FortiGate External Connector."""
    filepath = validate_filename(filename)
    
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    with file_lock(filepath, 'r') as f:
        if f:
            content = f.read()
            return PlainTextResponse(content, media_type="text/plain")
    
    return PlainTextResponse("", media_type="text/plain")

# ==============================================================================
# FRONTEND HTML
# ==============================================================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiGate List Manager</title>
    <style>
        :root {
            --bg-primary: #0f0f1a;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --bg-hover: #1e3a5f;
            --accent: #e94560;
            --accent-hover: #ff6b8a;
            --success: #00d084;
            --warning: #ffb020;
            --danger: #ff4757;
            --text-primary: #ffffff;
            --text-secondary: #a0a0b0;
            --border: #2a2a4a;
            --shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }
        
        /* Header */
        .app-header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
            padding: 20px 30px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(10px);
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent) 0%, #ff6b8a 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        
        .logo h1 {
            font-size: 1.4rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .logo span {
            font-size: 0.75rem;
            color: var(--text-secondary);
            display: block;
        }
        
        /* Stats bar */
        .stats-bar {
            display: flex;
            gap: 20px;
        }
        
        .stat-item {
            text-align: center;
            padding: 8px 16px;
            background: var(--bg-primary);
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
        }
        
        .stat-label {
            font-size: 0.7rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Main layout */
        .app-container {
            display: flex;
            min-height: calc(100vh - 81px);
        }
        
        /* Sidebar */
        .sidebar {
            width: 300px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            transition: width 0.3s;
        }
        
        .sidebar-header {
            padding: 20px;
            border-bottom: 1px solid var(--border);
        }
        
        .search-box {
            position: relative;
        }
        
        .search-box input {
            width: 100%;
            padding: 12px 15px 12px 40px;
            background: var(--bg-primary);
            border: 2px solid var(--border);
            border-radius: 10px;
            color: var(--text-primary);
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(233,69,96,0.2);
        }
        
        .search-box::before {
            content: "🔍";
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 14px;
        }
        
        .file-list-container {
            flex: 1;
            overflow-y: auto;
            padding: 15px;
        }
        
        .file-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .file-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.3s;
            border: 2px solid transparent;
            position: relative;
            overflow: hidden;
        }
        
        .file-card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent);
            transform: scaleY(0);
            transition: transform 0.3s;
        }
        
        .file-card:hover {
            background: var(--bg-hover);
            transform: translateX(5px);
        }
        
        .file-card:hover::before {
            transform: scaleY(1);
        }
        
        .file-card.active {
            border-color: var(--accent);
            background: var(--bg-hover);
        }
        
        .file-card.active::before {
            transform: scaleY(1);
        }
        
        .file-card-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
        }
        
        .file-icon {
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            flex-shrink: 0;
        }
        
        .file-icon.ip { background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); }
        .file-icon.domain { background: linear-gradient(135deg, #27ae60 0%, #1e8449 100%); }
        .file-icon.url { background: linear-gradient(135deg, #e67e22 0%, #d35400 100%); }
        .file-icon.block { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .file-icon.allow { background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); }
        
        .file-info {
            flex: 1;
            min-width: 0;
        }
        
        .file-name {
            font-weight: 600;
            font-size: 0.95rem;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .file-meta {
            display: flex;
            gap: 15px;
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 4px;
        }
        
        .file-stats {
            display: flex;
            gap: 10px;
        }
        
        .file-stat {
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 4px 10px;
            background: var(--bg-primary);
            border-radius: 20px;
            font-size: 0.75rem;
        }
        
        .file-stat.entries { color: var(--success); }
        
        /* Main content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        /* Welcome / File view */
        .view-container {
            flex: 1;
            overflow-y: auto;
            padding: 30px;
        }
        
        /* Welcome screen */
        .welcome-screen {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 60vh;
            text-align: center;
        }
        
        .welcome-icon {
            width: 120px;
            height: 120px;
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-hover) 100%);
            border-radius: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 50px;
            margin-bottom: 30px;
            animation: float 3s ease-in-out infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        .welcome-screen h2 {
            font-size: 1.8rem;
            margin-bottom: 10px;
            color: var(--text-primary);
        }
        
        .welcome-screen p {
            color: var(--text-secondary);
            max-width: 400px;
        }
        
        /* File view header */
        .file-view-header {
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-hover) 100%);
            padding: 25px 30px;
            border-radius: 16px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .file-title {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .file-title-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--accent) 0%, #ff6b8a 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        
        .file-title h2 {
            font-size: 1.5rem;
        }
        
        .file-title .badge {
            background: var(--accent);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .header-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        /* Buttons */
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--accent) 0%, #ff6b8a 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(233,69,96,0.4);
        }
        
        .btn-secondary {
            background: var(--bg-primary);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:hover {
            background: var(--bg-hover);
            border-color: var(--accent);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success) 0%, #00b871 100%);
            color: white;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger) 0%, #ee3b4d 100%);
            color: white;
        }
        
        .btn-icon {
            padding: 10px;
            border-radius: 8px;
        }
        
        /* Add entry form */
        .add-entry-form {
            display: flex;
            gap: 12px;
            margin-bottom: 25px;
        }
        
        .add-entry-form input {
            flex: 1;
            padding: 14px 18px;
            background: var(--bg-card);
            border: 2px solid var(--border);
            border-radius: 10px;
            color: var(--text-primary);
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .add-entry-form input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(233,69,96,0.2);
        }
        
        /* Search entries */
        .entries-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .entries-search {
            position: relative;
            width: 300px;
        }
        
        .entries-search input {
            width: 100%;
            padding: 10px 15px 10px 40px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
        }
        
        .entries-search::before {
            content: "🔍";
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 12px;
        }
        
        .entries-info {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        /* Entries table */
        .entries-table-wrapper {
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        
        .entries-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .entries-table th {
            background: var(--bg-primary);
            padding: 15px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border);
        }
        
        .entries-table td {
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            transition: background 0.2s;
        }
        
        .entries-table tr:last-child td {
            border-bottom: none;
        }
        
        .entries-table tr:hover td {
            background: var(--bg-hover);
        }
        
        .line-num {
            width: 60px;
            color: var(--text-secondary);
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.85rem;
        }
        
        .entry-value {
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9rem;
            word-break: break-all;
        }
        
        .entry-input {
            width: 100%;
            padding: 10px 14px;
            background: var(--bg-primary);
            border: 2px solid var(--accent);
            border-radius: 6px;
            color: var(--text-primary);
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9rem;
        }
        
        .actions-cell {
            width: 160px;
        }
        
        .actions-cell .btn {
            padding: 6px 12px;
            font-size: 12px;
        }
        
        /* Empty state */
        .empty-entries {
            text-align: center;
            padding: 60px 20px;
        }
        
        .empty-entries-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        
        .empty-entries h3 {
            color: var(--text-secondary);
            font-weight: 500;
            margin-bottom: 8px;
        }
        
        .empty-entries p {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            backdrop-filter: blur(5px);
        }
        
        .modal {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 16px;
            max-width: 450px;
            width: 90%;
            border: 1px solid var(--border);
            animation: modalIn 0.3s ease;
        }
        
        @keyframes modalIn {
            from { transform: scale(0.9); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }
        
        .modal-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .modal-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--danger) 0%, #ee3b4d 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        
        .modal h3 {
            font-size: 1.3rem;
        }
        
        .modal p {
            color: var(--text-secondary);
            margin-bottom: 25px;
            line-height: 1.7;
        }
        
        .modal code {
            background: var(--bg-primary);
            padding: 4px 10px;
            border-radius: 6px;
            font-family: 'Monaco', 'Consolas', monospace;
            color: var(--accent);
        }
        
        .modal-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }
        
        /* Toast notifications */
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            padding: 16px 24px;
            border-radius: 12px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 12px;
            z-index: 1001;
            animation: toastIn 0.4s ease;
            box-shadow: var(--shadow);
        }
        
        @keyframes toastIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .toast.success {
            background: linear-gradient(135deg, var(--success) 0%, #00b871 100%);
            color: white;
        }
        
        .toast.error {
            background: linear-gradient(135deg, var(--danger) 0%, #ee3b4d 100%);
            color: white;
        }
        
        .toast-icon { font-size: 18px; }
        
        /* Responsive */
        @media (max-width: 900px) {
            .app-container { flex-direction: column; }
            .sidebar { width: 100%; border-right: none; border-bottom: 1px solid var(--border); max-height: 40vh; }
            .stats-bar { display: none; }
        }
        
        @media (max-width: 600px) {
            .file-view-header { flex-direction: column; align-items: flex-start; }
            .header-actions { width: 100%; }
            .header-actions .btn { flex: 1; justify-content: center; }
            .add-entry-form { flex-direction: column; }
            .entries-search { width: 100%; }
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-primary); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--accent); }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="app-header">
        <div class="logo">
            <div class="logo-icon">🛡️</div>
            <div>
                <h1>FortiGate List Manager</h1>
                <span>External Connector Management</span>
            </div>
        </div>
        <div class="stats-bar" id="statsBar">
            <div class="stat-item">
                <div class="stat-value" id="totalFiles">-</div>
                <div class="stat-label">Files</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="totalEntries">-</div>
                <div class="stat-label">Total Entries</div>
            </div>
        </div>
    </header>

    <!-- Main container -->
    <div class="app-container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="search-box">
                    <input type="text" id="fileSearch" placeholder="Search files..." oninput="filterFiles()">
                </div>
            </div>
            <div class="file-list-container">
                <ul class="file-list" id="fileList">
                    <li class="empty-entries" style="padding:40px">
                        <div class="empty-entries-icon">⏳</div>
                        <h3>Loading files...</h3>
                    </li>
                </ul>
            </div>
        </aside>

        <!-- Main content -->
        <main class="main-content">
            <div class="view-container" id="viewContainer">
                <div class="welcome-screen">
                    <div class="welcome-icon">📂</div>
                    <h2>Welcome to List Manager</h2>
                    <p>Select a file from the sidebar to view and manage its entries. These lists are used for FortiGate External Connectors.</p>
                </div>
            </div>
        </main>
    </div>

    <!-- Modal -->
    <div id="modal" class="modal-overlay" style="display: none;">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-icon">⚠️</div>
                <h3>Confirm Delete</h3>
            </div>
            <p>Are you sure you want to delete this entry?<br><code id="modalValue"></code></p>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button class="btn btn-danger" id="modalConfirm">Delete</button>
            </div>
        </div>
    </div>

    <script>
        // State
        let currentFile = null;
        let entries = [];
        let allFiles = [];
        let filesData = {};
        let editingIndex = null;
        let searchTerm = '';

        // DOM Elements
        const fileList = document.getElementById('fileList');
        const viewContainer = document.getElementById('viewContainer');
        const modal = document.getElementById('modal');
        const modalValue = document.getElementById('modalValue');
        const modalConfirm = document.getElementById('modalConfirm');

        // Initialize
        document.addEventListener('DOMContentLoaded', init);

        async function init() {
            await loadFilesWithDetails();
        }

        // Load files with entry counts
        async function loadFilesWithDetails() {
            try {
                const res = await fetch('/api/files');
                const data = await res.json();
                allFiles = data.files;
                
                // Load entry counts for each file
                let totalEntries = 0;
                for (const file of allFiles) {
                    try {
                        const fileRes = await fetch('/api/files/' + encodeURIComponent(file));
                        const fileData = await fileRes.json();
                        filesData[file] = fileData;
                        totalEntries += fileData.count;
                        console.log('Loaded', file, ':', fileData.count, 'entries');
                    } catch (e) {
                        console.error('Error loading', file, ':', e);
                        filesData[file] = { entries: [], count: 0 };
                    }
                }
                
                // Update stats
                document.getElementById('totalFiles').textContent = allFiles.length;
                document.getElementById('totalEntries').textContent = totalEntries;
                
                renderFileList();
                
                if (currentFile && allFiles.includes(currentFile)) {
                    entries = filesData[currentFile]?.entries || [];
                    renderFileView(currentFile);
                }
            } catch (err) {
                console.error('Failed to load files:', err);
                fileList.innerHTML = '<li class="empty-entries"><div class="empty-entries-icon">❌</div><h3>Error loading files</h3></li>';
            }
        }

        // Get icon type based on filename
        function getFileIconType(filename) {
            const name = filename.toLowerCase();
            if (name.includes('ip') || name.includes('address')) return 'ip';
            if (name.includes('domain') || name.includes('fqdn')) return 'domain';
            if (name.includes('url') || name.includes('web')) return 'url';
            if (name.includes('block') || name.includes('deny') || name.includes('bad')) return 'block';
            if (name.includes('allow') || name.includes('permit') || name.includes('good')) return 'allow';
            return '';
        }

        // Filter files
        function filterFiles() {
            searchTerm = document.getElementById('fileSearch').value.toLowerCase();
            renderFileList();
        }

        // Render file list
        function renderFileList() {
            const filtered = allFiles.filter(f => f.toLowerCase().includes(searchTerm));
            
            if (filtered.length === 0) {
                fileList.innerHTML = '<li class="empty-entries"><div class="empty-entries-icon">📭</div><h3>No files found</h3></li>';
                return;
            }
            
            fileList.innerHTML = filtered.map(file => {
                const data = filesData[file] || { count: 0 };
                const iconType = getFileIconType(file);
                const isActive = file === currentFile;
                
                return '<li class="file-card' + (isActive ? ' active' : '') + '" onclick="selectFile(\\'' + file + '\\')" data-filename="' + file + '">' +
                    '<div class="file-card-header">' +
                        '<div class="file-icon ' + iconType + '">📄</div>' +
                        '<div class="file-info">' +
                            '<div class="file-name">' + file + '</div>' +
                            '<div class="file-meta">' +
                                '<span>Text File</span>' +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="file-stats">' +
                        '<span class="file-stat entries">📝 ' + data.count + ' entries</span>' +
                    '</div>' +
                '</li>';
            }).join('');
        }

        // Select file - always fetch fresh data
        async function selectFile(filename) {
            currentFile = filename;
            renderFileList();
            
            // Show loading state
            viewContainer.innerHTML = '<div class="empty-entries" style="padding:60px"><div class="empty-entries-icon">⏳</div><h3>Loading...</h3></div>';
            
            try {
                console.log('Fetching file:', filename);
                const res = await fetch('/api/files/' + encodeURIComponent(filename));
                console.log('Response status:', res.status);
                if (!res.ok) throw new Error('Failed to load file: ' + res.status);
                const data = await res.json();
                console.log('Loaded data:', data);
                console.log('Entries count:', data.entries?.length);
                filesData[filename] = data;
                entries = data.entries || [];
                console.log('Global entries set to:', entries.length);
                renderFileView(filename);
            } catch (err) {
                console.error('Error loading file:', err);
                viewContainer.innerHTML = '<div class="empty-entries" style="padding:60px"><div class="empty-entries-icon">❌</div><h3>Error loading file</h3><p>' + err.message + '</p></div>';
            }
        }

        // Render file view
        function renderFileView(filename) {
            console.log('renderFileView called with:', filename, 'entries:', entries.length);
            const data = filesData[filename] || { entries: [], count: 0 };
            const entryCount = entries.length;
            const exportUrl = window.location.protocol + '//' + window.location.host + '/export/' + encodeURIComponent(filename);
            
            // Clear and build view container
            viewContainer.innerHTML = '';
            
            // Header
            const header = document.createElement('div');
            header.className = 'file-view-header';
            header.innerHTML = '<div class="file-title"><div class="file-title-icon">📄</div><div><h2>' + escapeHtml(filename) + '</h2><span class="badge">' + entryCount + ' entries</span></div></div>';
            
            const headerActions = document.createElement('div');
            headerActions.className = 'header-actions';
            
            const btnCopy = document.createElement('button');
            btnCopy.className = 'btn btn-secondary';
            btnCopy.innerHTML = '🔗 Copy URL';
            btnCopy.onclick = () => copyExportUrl(exportUrl);
            
            const btnRefresh = document.createElement('button');
            btnRefresh.className = 'btn btn-secondary';
            btnRefresh.innerHTML = '🔄 Refresh';
            btnRefresh.onclick = () => refreshFile(filename);
            
            headerActions.appendChild(btnCopy);
            headerActions.appendChild(btnRefresh);
            header.appendChild(headerActions);
            viewContainer.appendChild(header);
            
            // Add form
            const addForm = document.createElement('div');
            addForm.className = 'add-entry-form';
            
            const inputNew = document.createElement('input');
            inputNew.type = 'text';
            inputNew.id = 'newEntry';
            inputNew.placeholder = 'Enter new FQDN, IP, or URL...';
            inputNew.onkeypress = (e) => { if (e.key === 'Enter') addEntry(); };
            
            const btnAdd = document.createElement('button');
            btnAdd.className = 'btn btn-primary';
            btnAdd.textContent = '+ Add Entry';
            btnAdd.onclick = addEntry;
            
            addForm.appendChild(inputNew);
            addForm.appendChild(btnAdd);
            viewContainer.appendChild(addForm);
            
            // Toolbar
            const toolbar = document.createElement('div');
            toolbar.className = 'entries-toolbar';
            toolbar.innerHTML = '<div class="entries-search"><input type="text" id="entrySearch" placeholder="Filter entries..." oninput="filterEntries()"></div><div class="entries-info">Showing <strong>' + entryCount + '</strong> entries</div>';
            viewContainer.appendChild(toolbar);
            
            // Table or empty state
            const tableWrapper = document.createElement('div');
            tableWrapper.className = 'entries-table-wrapper';
            
            if (entryCount === 0) {
                tableWrapper.innerHTML = '<div class="empty-entries"><div class="empty-entries-icon">📝</div><h3>No entries yet</h3><p>Add your first entry using the form above</p></div>';
            } else {
                const table = document.createElement('table');
                table.className = 'entries-table';
                table.innerHTML = '<thead><tr><th>Line</th><th>Value</th><th>Actions</th></tr></thead>';
                
                const tbody = document.createElement('tbody');
                tbody.id = 'entriesBody';
                
                entries.forEach(e => {
                    const tr = document.createElement('tr');
                    tr.id = 'row-' + e.index;
                    
                    const tdLine = document.createElement('td');
                    tdLine.className = 'line-num';
                    tdLine.textContent = e.index + 1;
                    tr.appendChild(tdLine);
                    
                    const tdValue = document.createElement('td');
                    tdValue.className = 'entry-value';
                    if (editingIndex === e.index) {
                        const input = document.createElement('input');
                        input.type = 'text';
                        input.className = 'entry-input';
                        input.id = 'edit-' + e.index;
                        input.value = e.value;
                        input.onkeypress = (ev) => { if (ev.key === 'Enter') saveEdit(e.index); };
                        input.onkeydown = (ev) => { if (ev.key === 'Escape') cancelEdit(); };
                        tdValue.appendChild(input);
                    } else {
                        tdValue.textContent = e.value;
                    }
                    tr.appendChild(tdValue);
                    
                    const tdActions = document.createElement('td');
                    tdActions.className = 'actions-cell';
                    
                    if (editingIndex === e.index) {
                        const btnSave = document.createElement('button');
                        btnSave.className = 'btn btn-success';
                        btnSave.textContent = 'Save';
                        btnSave.onclick = () => saveEdit(e.index);
                        
                        const btnCancel = document.createElement('button');
                        btnCancel.className = 'btn btn-secondary';
                        btnCancel.textContent = 'Cancel';
                        btnCancel.onclick = cancelEdit;
                        
                        tdActions.appendChild(btnSave);
                        tdActions.appendChild(document.createTextNode(' '));
                        tdActions.appendChild(btnCancel);
                    } else {
                        const btnEdit = document.createElement('button');
                        btnEdit.className = 'btn btn-secondary';
                        btnEdit.textContent = 'Edit';
                        btnEdit.onclick = () => startEdit(e.index);
                        
                        const btnDelete = document.createElement('button');
                        btnDelete.className = 'btn btn-danger';
                        btnDelete.textContent = 'Delete';
                        btnDelete.onclick = () => confirmDelete(e.index, e.value);
                        
                        tdActions.appendChild(btnEdit);
                        tdActions.appendChild(document.createTextNode(' '));
                        tdActions.appendChild(btnDelete);
                    }
                    tr.appendChild(tdActions);
                    tbody.appendChild(tr);
                });
                
                table.appendChild(tbody);
                tableWrapper.appendChild(table);
            }
            
            viewContainer.appendChild(tableWrapper);
            
            if (editingIndex !== null) {
                const input = document.getElementById('edit-' + editingIndex);
                if (input) { input.focus(); input.select(); }
            }
        }

        // Render entries rows
        function renderEntriesRows() {
            const filter = document.getElementById('entrySearch')?.value?.toLowerCase() || '';
            const filtered = entries.filter(e => e.value.toLowerCase().includes(filter));
            
            const tbody = document.createElement('tbody');
            tbody.id = 'entriesBody';
            
            filtered.forEach(e => {
                const tr = document.createElement('tr');
                tr.id = 'row-' + e.index;
                
                // Line number
                const tdLine = document.createElement('td');
                tdLine.className = 'line-num';
                tdLine.textContent = e.index + 1;
                tr.appendChild(tdLine);
                
                // Value
                const tdValue = document.createElement('td');
                tdValue.className = 'entry-value';
                if (editingIndex === e.index) {
                    const input = document.createElement('input');
                    input.type = 'text';
                    input.className = 'entry-input';
                    input.id = 'edit-' + e.index;
                    input.value = e.value;
                    input.onkeypress = (ev) => { if (ev.key === 'Enter') saveEdit(e.index); };
                    input.onkeydown = (ev) => { if (ev.key === 'Escape') cancelEdit(); };
                    tdValue.appendChild(input);
                } else {
                    tdValue.textContent = e.value;
                }
                tr.appendChild(tdValue);
                
                // Actions
                const tdActions = document.createElement('td');
                tdActions.className = 'actions-cell';
                if (editingIndex === e.index) {
                    const btnSave = document.createElement('button');
                    btnSave.className = 'btn btn-success';
                    btnSave.textContent = 'Save';
                    btnSave.onclick = () => saveEdit(e.index);
                    
                    const btnCancel = document.createElement('button');
                    btnCancel.className = 'btn btn-secondary';
                    btnCancel.textContent = 'Cancel';
                    btnCancel.onclick = cancelEdit;
                    
                    tdActions.appendChild(btnSave);
                    tdActions.appendChild(document.createTextNode(' '));
                    tdActions.appendChild(btnCancel);
                } else {
                    const btnEdit = document.createElement('button');
                    btnEdit.className = 'btn btn-secondary';
                    btnEdit.textContent = 'Edit';
                    btnEdit.onclick = () => startEdit(e.index);
                    
                    const btnDelete = document.createElement('button');
                    btnDelete.className = 'btn btn-danger';
                    btnDelete.textContent = 'Delete';
                    btnDelete.onclick = () => confirmDelete(e.index, e.value);
                    
                    tdActions.appendChild(btnEdit);
                    tdActions.appendChild(document.createTextNode(' '));
                    tdActions.appendChild(btnDelete);
                }
                tr.appendChild(tdActions);
                
                tbody.appendChild(tr);
            });
            
            return tbody.innerHTML;
        }

        // Filter entries
        function filterEntries() {
            const tbody = document.getElementById('entriesBody');
            if (tbody) {
                // Create new tbody with proper event handlers
                const newTbody = document.createElement('tbody');
                newTbody.id = 'entriesBody';
                
                const filter = document.getElementById('entrySearch')?.value?.toLowerCase() || '';
                const filtered = entries.filter(e => e.value.toLowerCase().includes(filter));
                
                filtered.forEach(e => {
                    const tr = document.createElement('tr');
                    tr.id = 'row-' + e.index;
                    
                    const tdLine = document.createElement('td');
                    tdLine.className = 'line-num';
                    tdLine.textContent = e.index + 1;
                    tr.appendChild(tdLine);
                    
                    const tdValue = document.createElement('td');
                    tdValue.className = 'entry-value';
                    tdValue.textContent = e.value;
                    tr.appendChild(tdValue);
                    
                    const tdActions = document.createElement('td');
                    tdActions.className = 'actions-cell';
                    
                    const btnEdit = document.createElement('button');
                    btnEdit.className = 'btn btn-secondary';
                    btnEdit.textContent = 'Edit';
                    btnEdit.onclick = () => startEdit(e.index);
                    
                    const btnDelete = document.createElement('button');
                    btnDelete.className = 'btn btn-danger';
                    btnDelete.textContent = 'Delete';
                    btnDelete.onclick = () => confirmDelete(e.index, e.value);
                    
                    tdActions.appendChild(btnEdit);
                    tdActions.appendChild(document.createTextNode(' '));
                    tdActions.appendChild(btnDelete);
                    tr.appendChild(tdActions);
                    
                    newTbody.appendChild(tr);
                });
                
                tbody.parentNode.replaceChild(newTbody, tbody);
                document.querySelector('.entries-info').innerHTML = 'Showing <strong>' + filtered.length + '</strong> of ' + entries.length + ' entries';
            }
        }

        // Refresh file
        async function refreshFile(filename) {
            try {
                const res = await fetch('/api/files/' + encodeURIComponent(filename));
                const data = await res.json();
                filesData[filename] = data;
                entries = data.entries || [];
                renderFileList();
                renderFileView(filename);
                showToast('File refreshed', 'success');
            } catch (err) {
                showToast('Failed to refresh', 'error');
            }
        }

        // Add entry
        async function addEntry() {
            const input = document.getElementById('newEntry');
            const value = input.value.trim();
            if (!value) { showToast('Please enter a value', 'error'); return; }
            
            try {
                const res = await fetch('/api/files/' + currentFile, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to add');
                
                input.value = '';
                showToast('Entry added successfully', 'success');
                await refreshFile(currentFile);
                await loadFilesWithDetails();
            } catch (err) {
                showToast(err.message, 'error');
            }
        }

        // Edit functions
        function startEdit(index) { editingIndex = index; renderFileView(currentFile); }
        function cancelEdit() { editingIndex = null; renderFileView(currentFile); }

        async function saveEdit(index) {
            const input = document.getElementById('edit-' + index);
            const value = input.value.trim();
            if (!value) { showToast('Value cannot be empty', 'error'); return; }
            
            try {
                const res = await fetch('/api/files/' + currentFile + '/' + index, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to update');
                
                editingIndex = null;
                showToast('Entry updated', 'success');
                await refreshFile(currentFile);
            } catch (err) {
                showToast(err.message, 'error');
            }
        }

        // Delete functions
        function confirmDelete(index, value) {
            modalValue.textContent = value;
            modal.style.display = 'flex';
            modalConfirm.onclick = () => deleteEntry(index);
        }

        function closeModal() { modal.style.display = 'none'; }

        async function deleteEntry(index) {
            closeModal();
            try {
                const res = await fetch('/api/files/' + currentFile + '/' + index, { method: 'DELETE' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to delete');
                
                showToast('Entry deleted', 'success');
                await refreshFile(currentFile);
                await loadFilesWithDetails();
            } catch (err) {
                showToast(err.message, 'error');
            }
        }

        // Copy URL
        async function copyExportUrl(url) {
            try {
                await navigator.clipboard.writeText(url);
                showToast('URL copied to clipboard!', 'success');
            } catch (err) {
                const input = document.createElement('input');
                input.value = url;
                document.body.appendChild(input);
                input.select();
                document.execCommand('copy');
                document.body.removeChild(input);
                showToast('URL copied!', 'success');
            }
        }

        // Toast notification
        function showToast(message, type) {
            const existing = document.querySelector('.toast');
            if (existing) existing.remove();
            
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.innerHTML = '<span class="toast-icon">' + (type === 'success' ? '✓' : '✕') + '</span> ' + message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        // Helpers
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function escapeJs(text) {
            return text.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/"/g, '\\\\"');
        }

        // Event listeners
        modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') { closeModal(); if (editingIndex !== null) cancelEdit(); }
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    """Serve the web UI."""
    return HTML_TEMPLATE

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    import sys
    
    # Safety check: do not run as root
    if os.geteuid() == 0:
        print("ERROR: This application must NOT run as root!", file=sys.stderr)
        print("Please run as a non-privileged user.", file=sys.stderr)
        sys.exit(1)
    
    # Ensure base directory exists
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"Starting FortiGate List Manager on port {PORT}...")
    print(f"Managing files in: {BASE_DIR}")
    print(f"Web UI: http://0.0.0.0:{PORT}/")
    print(f"Export endpoint: http://0.0.0.0:{PORT}/export/{{filename}}")
    
    # Run with uvicorn (single worker for simplicity, use gunicorn for production)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True
    )
