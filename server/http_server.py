#!/usr/bin/env python3
"""
Simple HTTP server for hosting PowerShell scripts and payloads
Used by GonkWare to serve files like Invoke-Mimikatz.ps1 to target systems
"""

import http.server
import socketserver
import threading
import os
import logging

logger = logging.getLogger(__name__)

class GonkWareHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler for GonkWare file serving"""
    
    def __init__(self, *args, **kwargs):
        # Serve files from the scripts directory
        super().__init__(*args, directory="server/scripts", **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logger instead of printing to stderr"""
        logger.info(f"HTTP Request: {format % args}")
    
    def end_headers(self):
        # Add CORS headers to allow cross-origin requests
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

class GonkWareHTTPServer:
    """HTTP server manager for GonkWare"""
    
    def __init__(self, port=8080, interface="0.0.0.0"):
        self.port = port
        self.interface = interface
        self.server = None
        self.server_thread = None
        self.running = False
    
    def start_server(self):
        """Start the HTTP server in a background thread"""
        if self.running:
            logger.warning("HTTP server already running")
            return False
        
        try:
            # Create server
            self.server = socketserver.TCPServer((self.interface, self.port), GonkWareHTTPHandler)
            self.server.allow_reuse_address = True
            
            # Start server in background thread
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            self.running = True
            logger.info(f"HTTP server started on {self.interface}:{self.port}")
            logger.info(f"Serving files from: {os.path.abspath('server/scripts')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start HTTP server: {e}")
            return False
    
    def stop_server(self):
        """Stop the HTTP server"""
        if not self.running:
            logger.warning("HTTP server not running")
            return
        
        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
            
            if self.server_thread:
                self.server_thread.join(timeout=5)
            
            self.running = False
            logger.info("HTTP server stopped")
            
        except Exception as e:
            logger.error(f"Error stopping HTTP server: {e}")
    
    def is_running(self):
        """Check if server is running"""
        return self.running
    
    def get_server_url(self, filename=""):
        """Get the full URL for a file"""
        if filename:
            return f"http://{self.interface}:{self.port}/{filename}"
        else:
            return f"http://{self.interface}:{self.port}/"

# Global server instance
http_server = None

def start_http_server(port=8080, interface="0.0.0.0"):
    """Start the global HTTP server"""
    global http_server
    
    if http_server and http_server.is_running():
        logger.warning("HTTP server already running")
        return http_server
    
    http_server = GonkWareHTTPServer(port, interface)
    if http_server.start_server():
        return http_server
    else:
        http_server = None
        return None

def stop_http_server():
    """Stop the global HTTP server"""
    global http_server
    
    if http_server:
        http_server.stop_server()
        http_server = None

def get_http_server():
    """Get the global HTTP server instance"""
    return http_server
