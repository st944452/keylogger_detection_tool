from flask import Flask, render_template, jsonify, request
import psutil
import threading
import time
import json
from datetime import datetime
from security_monitor import SecurityMonitor
from keylogger_detector import KeyloggerDetector

app = Flask(__name__)

# Initialize security components
security_monitor = SecurityMonitor()
keylogger_detector = KeyloggerDetector()

# Global variables for monitoring data
monitoring_data = {
    'alerts': [],
    'system_stats': {},
    'suspicious_processes': [],
    'keyboard_patterns': [],
    'last_update': None
}

def background_monitor():
    """Background thread for continuous monitoring"""
    while True:
        try:
            # Update system statistics
            monitoring_data['system_stats'] = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections()),
                'running_processes': len(psutil.pids())
            }
            
            # Check for suspicious processes
            suspicious = security_monitor.scan_processes()
            if suspicious:
                monitoring_data['suspicious_processes'] = suspicious
                monitoring_data['alerts'].append({
                    'type': 'process',
                    'message': f'Detected {len(suspicious)} suspicious processes',
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'high'
                })
            
            # Analyze keyboard patterns
            patterns = keylogger_detector.analyze_patterns()
            if patterns:
                monitoring_data['keyboard_patterns'] = patterns
            
            monitoring_data['last_update'] = datetime.now().isoformat()
            
            # Limit alerts to last 50
            if len(monitoring_data['alerts']) > 50:
                monitoring_data['alerts'] = monitoring_data['alerts'][-50:]
                
        except Exception as e:
            print(f"Background monitor error: {e}")
        
        time.sleep(5)

# Start background monitoring
monitor_thread = threading.Thread(target=background_monitor, daemon=True)
monitor_thread.start()

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Security monitoring dashboard"""
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    """Get current system status"""
    return jsonify({
        'status': 'active',
        'monitoring': True,
        'last_update': monitoring_data['last_update'],
        'alerts_count': len(monitoring_data['alerts'])
    })

@app.route('/api/system-stats')
def api_system_stats():
    """Get current system statistics"""
    return jsonify(monitoring_data['system_stats'])

@app.route('/api/alerts')
def api_alerts():
    """Get recent security alerts"""
    return jsonify(monitoring_data['alerts'])

@app.route('/api/suspicious-processes')
def api_suspicious_processes():
    """Get list of suspicious processes"""
    return jsonify(monitoring_data['suspicious_processes'])

@app.route('/api/keyboard-patterns')
def api_keyboard_patterns():
    """Get keyboard behavior analysis"""
    return jsonify(monitoring_data['keyboard_patterns'])

@app.route('/api/scan-now', methods=['POST'])
def api_scan_now():
    """Trigger immediate security scan"""
    try:
        # Perform immediate scan
        suspicious_processes = security_monitor.scan_processes()
        network_analysis = security_monitor.analyze_network()
        
        # Add alert for manual scan
        monitoring_data['alerts'].append({
            'type': 'manual_scan',
            'message': f'Manual scan completed - Found {len(suspicious_processes)} suspicious items',
            'timestamp': datetime.now().isoformat(),
            'severity': 'info'
        })
        
        return jsonify({
            'success': True,
            'suspicious_processes': len(suspicious_processes),
            'network_connections': network_analysis
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/keyboard-event', methods=['POST'])
def api_keyboard_event():
    """Receive keyboard event data for analysis"""
    try:
        data = request.get_json()
        
        # Analyze the keyboard event
        analysis = keylogger_detector.analyze_event(data)
        
        if analysis.get('suspicious', False):
            monitoring_data['alerts'].append({
                'type': 'keyboard',
                'message': analysis.get('message', 'Suspicious keyboard activity detected'),
                'timestamp': datetime.now().isoformat(),
                'severity': analysis.get('severity', 'medium')
            })
        
        return jsonify({'success': True, 'analysis': analysis})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/process-details/<int:pid>')
def api_process_details(pid):
    """Get detailed information about a specific process"""
    try:
        process = psutil.Process(pid)
        details = {
            'pid': pid,
            'name': process.name(),
            'exe': process.exe() if process.exe() else 'Unknown',
            'cmdline': ' '.join(process.cmdline()) if process.cmdline() else 'Unknown',
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
            'status': process.status(),
            'connections': len(process.connections()) if hasattr(process, 'connections') else 0
        }
        return jsonify(details)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Keylogger Detection Tool...")
    print("Access the web interface at: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
