from flask import Flask, request, jsonify, send_file, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import json
import time
import threading
from datetime import datetime, timedelta
import re
import geoip2.database
import pandas as pd
from collections import Counter
import hashlib
import tarfile
import zipfile

from log_parsers.nginx_parser import NginxParser
from log_parsers.mysql_parser import MySQLParser
from log_parsers.auth_parser import AuthParser
from log_parsers.syslog_parser import SyslogParser
from analyzers.security_analyzer import SecurityAnalyzer
from analyzers.performance_analyzer import PerformanceAnalyzer

app = Flask(__name__, static_folder='../frontend', template_folder='../frontend')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
UPLOAD_FOLDER = './uploads'
PROCESSED_FOLDER = './processed'
LOG_WATCH_FOLDER = '/var/log'
ALLOWED_EXTENSIONS = {'log', 'gz', 'zip', 'tar'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER

# Initialize parsers
nginx_parser = NginxParser()
mysql_parser = MySQLParser()
auth_parser = AuthParser()
syslog_parser = SyslogParser()
security_analyzer = SecurityAnalyzer()
performance_analyzer = PerformanceAnalyzer()

# Real-time monitoring threads
monitoring_threads = {}
geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    files = request.files.getlist('file')
    log_type = request.form.get('log_type', 'nginx')
    
    results = []
    for file in files:
        if file.filename == '':
            continue
        
        if file and allowed_file(file.filename):
            filename = hashlib.md5(f"{file.filename}{time.time()}".encode()).hexdigest()
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Process based on log type
            if log_type == 'nginx':
                result = nginx_parser.parse(filepath)
            elif log_type == 'mysql':
                result = mysql_parser.parse(filepath)
            elif log_type == 'auth':
                result = auth_parser.parse(filepath)
            elif log_type == 'syslog':
                result = syslog_parser.parse(filepath)
            else:
                result = {'error': 'Unknown log type'}
            
            results.append({
                'filename': file.filename,
                'analysis': result,
                'id': filename
            })
    
    return jsonify({'results': results})

@app.route('/api/monitor/start', methods=['POST'])
def start_monitoring():
    data = request.json
    log_path = data.get('log_path', '/var/log/nginx/access.log')
    log_type = data.get('log_type', 'nginx')
    
    if log_path in monitoring_threads:
        return jsonify({'error': 'Already monitoring this path'}), 400
    
    thread = threading.Thread(target=monitor_log_file, args=(log_path, log_type))
    thread.daemon = True
    thread.start()
    
    monitoring_threads[log_path] = thread
    return jsonify({'message': f'Started monitoring {log_path}'})

@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitoring():
    data = request.json
    log_path = data.get('log_path')
    
    if log_path in monitoring_threads:
        # Signal thread to stop
        monitoring_threads.pop(log_path)
        return jsonify({'message': f'Stopped monitoring {log_path}'})
    
    return jsonify({'error': 'Not monitoring this path'}), 400

def monitor_log_file(log_path, log_type):
    """Monitor log file in real-time"""
    try:
        with open(log_path, 'r') as f:
            # Go to end of file
            f.seek(0, 2)
            
            while log_path in monitoring_threads:
                line = f.readline()
                if line:
                    # Parse line based on log type
                    if log_type == 'nginx':
                        parsed = nginx_parser.parse_line(line)
                    elif log_type == 'mysql':
                        parsed = mysql_parser.parse_line(line)
                    else:
                        parsed = {'raw': line.strip()}
                    
                    # Emit via WebSocket
                    socketio.emit('log_entry', {
                        'log_path': log_path,
                        'timestamp': datetime.now().isoformat(),
                        'data': parsed
                    })
                    
                    # Check for security threats
                    threats = security_analyzer.analyze_line(line, log_type)
                    if threats:
                        socketio.emit('security_alert', {
                            'log_path': log_path,
                            'timestamp': datetime.now().isoformat(),
                            'threats': threats,
                            'severity': 'high'
                        })
                
                time.sleep(0.1)
    except Exception as e:
        socketio.emit('monitor_error', {
            'log_path': log_path,
            'error': str(e)
        })

@app.route('/api/analyze/security', methods=['POST'])
def analyze_security():
    data = request.json
    log_id = data.get('log_id')
    analysis_type = data.get('type', 'full')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], log_id)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    analysis = security_analyzer.analyze(content, analysis_type)
    return jsonify(analysis)

@app.route('/api/analyze/performance', methods=['POST'])
def analyze_performance():
    data = request.json
    log_id = data.get('log_id')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], log_id)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    if 'nginx' in filepath:
        with open(filepath, 'r') as f:
            logs = [nginx_parser.parse_line(line) for line in f if line.strip()]
        
        analysis = performance_analyzer.analyze_nginx(logs)
        return jsonify(analysis)
    
    return jsonify({'error': 'Unsupported log type for performance analysis'}), 400

@app.route('/api/geo/ip/<ip_address>')
def get_ip_geo(ip_address):
    try:
        response = geoip_reader.city(ip_address)
        return jsonify({
            'country': response.country.name,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude,
            'iso_code': response.country.iso_code
        })
    except:
        return jsonify({'error': 'IP not found'}), 404

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    # Aggregate statistics from all uploaded logs
    stats = {
        'total_logs': len(os.listdir(app.config['UPLOAD_FOLDER'])),
        'security_alerts': 0,
        'unique_ips': set(),
        'total_requests': 0,
        'errors': 0
    }
    
    # Process all uploaded files for statistics
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    stats['total_requests'] += 1
                    
                    # Extract IPs
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if ip_match:
                        stats['unique_ips'].add(ip_match.group())
                    
                    # Count errors
                    if 'error' in line.lower() or '401' in line or '403' in line or '404' in line or '500' in line:
                        stats['errors'] += 1
                    
                    # Check for security alerts
                    if security_analyzer.analyze_line(line, 'generic'):
                        stats['security_alerts'] += 1
        except:
            continue
    
    stats['unique_ips'] = len(stats['unique_ips'])
    
    return jsonify(stats)

@app.route('/api/export/<log_id>')
def export_analysis(log_id):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], log_id)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    # Create analysis report
    with open(filepath, 'r') as f:
        content = f.read()
    
    analysis = {
        'filename': log_id,
        'timestamp': datetime.now().isoformat(),
        'security_analysis': security_analyzer.analyze(content, 'full'),
        'size': os.path.getsize(filepath),
        'line_count': len(content.split('\n'))
    }
    
    # Save as JSON
    export_path = os.path.join(app.config['PROCESSED_FOLDER'], f"{log_id}_analysis.json")
    with open(export_path, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    return send_file(export_path, as_attachment=True)

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    # Create directories if they don't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(PROCESSED_FOLDER, exist_ok=True)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
