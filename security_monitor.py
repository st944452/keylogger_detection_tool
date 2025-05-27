import psutil
import re
import os
import hashlib
from datetime import datetime
import socket

class SecurityMonitor:
    """Security monitoring class for detecting suspicious system activity"""
    
    def __init__(self):
        # Known keylogger process names and patterns
        self.suspicious_patterns = [
            r'.*keylog.*',
            r'.*klog.*',
            r'.*spyware.*',
            r'.*spy.*',
            r'.*hook.*',
            r'.*capture.*',
            r'.*monitor.*key.*',
            r'.*input.*capture.*',
            r'.*screen.*capture.*',
            r'.*remote.*access.*'
        ]
        
        # Suspicious file paths
        self.suspicious_paths = [
            '/tmp/',
            '/var/tmp/',
            '\\temp\\',
            '\\appdata\\roaming\\',
            'startup',
            'autostart'
        ]
        
        # Known legitimate processes to whitelist
        self.whitelist = [
            'explorer.exe',
            'chrome.exe',
            'firefox.exe',
            'notepad.exe',
            'cmd.exe',
            'powershell.exe',
            'python.exe',
            'python3',
            'systemd',
            'kernel',
            'init'
        ]
    
    def scan_processes(self):
        """Scan running processes for suspicious activity"""
        suspicious_processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    
                    # Skip if process info is None
                    if not proc_info or not proc_info.get('name'):
                        continue
                    
                    process_name = proc_info['name'].lower()
                    
                    # Skip whitelisted processes
                    if any(white in process_name for white in self.whitelist):
                        continue
                    
                    # Check against suspicious patterns
                    is_suspicious = False
                    reason = []
                    
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, process_name, re.IGNORECASE):
                            is_suspicious = True
                            reason.append(f"Process name matches suspicious pattern: {pattern}")
                    
                    # Check executable path
                    if proc_info.get('exe'):
                        exe_path = proc_info['exe'].lower()
                        for sus_path in self.suspicious_paths:
                            if sus_path in exe_path:
                                is_suspicious = True
                                reason.append(f"Executable in suspicious path: {sus_path}")
                    
                    # Check command line arguments for suspicious keywords
                    if proc_info.get('cmdline'):
                        cmdline = ' '.join(proc_info['cmdline']).lower()
                        suspicious_keywords = ['keylog', 'hook', 'capture', 'spy', 'stealth', 'hidden']
                        for keyword in suspicious_keywords:
                            if keyword in cmdline:
                                is_suspicious = True
                                reason.append(f"Command line contains suspicious keyword: {keyword}")
                    
                    # Check for processes with high CPU usage that might be monitoring
                    try:
                        cpu_percent = proc.cpu_percent(interval=0.1)
                        if cpu_percent > 50:  # High CPU usage
                            reason.append(f"High CPU usage: {cpu_percent}%")
                    except:
                        pass
                    
                    if is_suspicious:
                        suspicious_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'exe': proc_info.get('exe', 'Unknown'),
                            'cmdline': ' '.join(proc_info.get('cmdline', [])),
                            'create_time': datetime.fromtimestamp(proc_info.get('create_time', 0)).isoformat(),
                            'reasons': reason,
                            'risk_level': self._calculate_risk_level(reason)
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    print(f"Error processing process: {e}")
                    continue
        
        except Exception as e:
            print(f"Error scanning processes: {e}")
        
        return suspicious_processes
    
    def analyze_network(self):
        """Analyze network connections for suspicious activity"""
        suspicious_connections = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    # Check for connections to suspicious ports or IPs
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Common keylogger/malware ports
                    suspicious_ports = [1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999]
                    
                    if remote_port in suspicious_ports:
                        suspicious_connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{remote_ip}:{remote_port}",
                            'status': conn.status,
                            'pid': conn.pid,
                            'reason': f"Connection to suspicious port {remote_port}"
                        })
                    
                    # Check for private IP ranges that might indicate C&C communication
                    if self._is_suspicious_ip(remote_ip):
                        suspicious_connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{remote_ip}:{remote_port}",
                            'status': conn.status,
                            'pid': conn.pid,
                            'reason': "Connection to potentially suspicious IP"
                        })
        
        except Exception as e:
            print(f"Error analyzing network: {e}")
        
        return suspicious_connections
    
    def _calculate_risk_level(self, reasons):
        """Calculate risk level based on suspicious indicators"""
        if len(reasons) >= 3:
            return 'high'
        elif len(reasons) >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _is_suspicious_ip(self, ip):
        """Check if IP address is suspicious"""
        # This is a simplified check - in production, you'd use threat intelligence feeds
        try:
            # Check if it's a known malicious IP range or unusual destination
            parts = ip.split('.')
            if len(parts) == 4:
                first_octet = int(parts[0])
                # Skip common legitimate ranges
                if first_octet in [8, 74, 142, 172, 173, 216]:  # Google, Facebook, etc.
                    return False
                # Flag some suspicious ranges
                if first_octet in [31, 46, 91, 146, 176, 185, 188]:
                    return True
        except:
            pass
        return False
    
    def get_system_info(self):
        """Get comprehensive system information"""
        try:
            return {
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_total': psutil.disk_usage('/').total,
                'platform': os.name,
                'hostname': socket.gethostname(),
                'users': [user.name for user in psutil.users()]
            }
        except Exception as e:
            print(f"Error getting system info: {e}")
            return {}
