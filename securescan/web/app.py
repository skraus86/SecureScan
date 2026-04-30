"""
Flask application for SecureScan Web UI
"""

import os
import uuid
import json
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory

from ..config import ScanConfig
from ..core import SecureScan
from ..models import ScanResult


# Store for scan results and status
scan_store = {}
scan_lock = threading.Lock()


def create_app(config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securescan-dev-key')
    app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', '/tmp/securescan-uploads')
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max
    
    if config:
        app.config.update(config)
    
    # Ensure upload folder exists
    Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
    
    register_routes(app)
    
    return app


def register_routes(app):
    """Register all routes"""
    
    @app.route('/')
    def index():
        """Main dashboard"""
        return render_template('index.html')
    
    @app.route('/scan')
    def scan_page():
        """Scan configuration page"""
        return render_template('scan.html')
    
    @app.route('/results')
    def results_page():
        """Results listing page"""
        return render_template('results.html')
    
    @app.route('/results/<scan_id>')
    def result_detail(scan_id):
        """Detailed result view"""
        return render_template('result_detail.html', scan_id=scan_id)
    
    # API Routes
    @app.route('/api/scan', methods=['POST'])
    def start_scan():
        """Start a new security scan"""
        data = request.get_json() or {}
        
        target_path = data.get('target_path', '.')
        
        # Validate path exists
        if not Path(target_path).exists():
            return jsonify({'error': f'Path does not exist: {target_path}'}), 400
        
        scan_id = str(uuid.uuid4())
        
        # Create scan config
        config = ScanConfig(
            target_path=target_path,
            output_dir=str(Path(app.config['UPLOAD_FOLDER']) / scan_id),
            sast_enabled=data.get('sast_enabled', True),
            sca_enabled=data.get('sca_enabled', True),
            secrets_enabled=data.get('secrets_enabled', True),
        )
        
        # Initialize scan status
        with scan_lock:
            scan_store[scan_id] = {
                'id': scan_id,
                'status': 'running',
                'target_path': target_path,
                'started_at': datetime.utcnow().isoformat(),
                'completed_at': None,
                'result': None,
                'error': None,
                'progress': 0,
            }
        
        # Run scan in background thread
        thread = threading.Thread(target=run_scan_async, args=(app, scan_id, config))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'running',
            'message': 'Scan started successfully'
        })
    
    @app.route('/api/scan/<scan_id>/status')
    def get_scan_status(scan_id):
        """Get scan status"""
        with scan_lock:
            if scan_id not in scan_store:
                return jsonify({'error': 'Scan not found'}), 404
            
            scan_info = scan_store[scan_id].copy()
            # Don't include full result in status check
            if scan_info.get('result'):
                scan_info['has_result'] = True
                del scan_info['result']
            
            return jsonify(scan_info)
    
    @app.route('/api/scan/<scan_id>/result')
    def get_scan_result(scan_id):
        """Get full scan result"""
        with scan_lock:
            if scan_id not in scan_store:
                return jsonify({'error': 'Scan not found'}), 404
            
            scan_info = scan_store[scan_id]
            
            if scan_info['status'] == 'running':
                return jsonify({'error': 'Scan still in progress'}), 202
            
            if scan_info['status'] == 'error':
                return jsonify({'error': scan_info['error']}), 500
            
            return jsonify(scan_info['result'])
    
    @app.route('/api/scans')
    def list_scans():
        """List all scans"""
        with scan_lock:
            scans = []
            for scan_id, info in scan_store.items():
                scan_summary = {
                    'id': info['id'],
                    'status': info['status'],
                    'target_path': info['target_path'],
                    'started_at': info['started_at'],
                    'completed_at': info['completed_at'],
                }
                if info.get('result'):
                    scan_summary['summary'] = info['result'].get('summary', {})
                scans.append(scan_summary)
            
            # Sort by start time, newest first
            scans.sort(key=lambda x: x['started_at'], reverse=True)
            
            return jsonify({'scans': scans})
    
    @app.route('/api/findings/<scan_id>')
    def get_findings(scan_id):
        """Get findings with filtering and sorting"""
        with scan_lock:
            if scan_id not in scan_store:
                return jsonify({'error': 'Scan not found'}), 404
            
            scan_info = scan_store[scan_id]
            
            if not scan_info.get('result'):
                return jsonify({'error': 'No results available'}), 404
            
            findings = scan_info['result'].get('findings', [])
        
        # Apply filters
        severity = request.args.get('severity')
        finding_type = request.args.get('type')
        search = request.args.get('search', '').lower()
        
        if severity and severity != 'all':
            findings = [f for f in findings if f['severity'] == severity]
        
        if finding_type and finding_type != 'all':
            findings = [f for f in findings if f['finding_type'] == finding_type]
        
        if search:
            findings = [f for f in findings if 
                       search in f['title'].lower() or 
                       search in f['description'].lower() or
                       search in f['location']['file_path'].lower()]
        
        # Sort by CVSS score (if available) then severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda f: (
            -(f.get('cvss_score') or 0),  # Higher CVSS first
            severity_order.get(f['severity'], 5)
        ))
        
        return jsonify({
            'findings': findings,
            'total': len(findings)
        })


def run_scan_async(app, scan_id, config):
    """Run scan in background thread"""
    try:
        with app.app_context():
            scanner = SecureScan(config)
            
            # Update progress
            with scan_lock:
                scan_store[scan_id]['progress'] = 10
            
            result = scanner.scan()
            
            with scan_lock:
                scan_store[scan_id]['progress'] = 90
            
            # Convert result to dict
            result_dict = result.to_dict()
            
            # Enrich findings with CVE severity mapping
            for finding in result_dict['findings']:
                finding['cve_severity'] = get_cve_severity(finding.get('cvss_score'))
            
            with scan_lock:
                scan_store[scan_id]['status'] = 'completed'
                scan_store[scan_id]['completed_at'] = datetime.utcnow().isoformat()
                scan_store[scan_id]['result'] = result_dict
                scan_store[scan_id]['progress'] = 100
                
    except Exception as e:
        with scan_lock:
            scan_store[scan_id]['status'] = 'error'
            scan_store[scan_id]['error'] = str(e)
            scan_store[scan_id]['completed_at'] = datetime.utcnow().isoformat()


def get_cve_severity(cvss_score):
    """
    Map CVSS score to CVE severity rating
    Based on CVSS v3.0 severity ratings:
    - Critical: 9.0 - 10.0
    - High: 7.0 - 8.9
    - Medium: 4.0 - 6.9
    - Low: 0.1 - 3.9
    - None: 0.0
    """
    if cvss_score is None:
        return None
    
    if cvss_score >= 9.0:
        return 'critical'
    elif cvss_score >= 7.0:
        return 'high'
    elif cvss_score >= 4.0:
        return 'medium'
    elif cvss_score >= 0.1:
        return 'low'
    else:
        return 'none'


def run_server(host='0.0.0.0', port=5000, debug=False):
    """Run the web server"""
    app = create_app()
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_server(debug=True)
