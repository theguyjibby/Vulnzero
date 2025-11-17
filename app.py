from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_cors import CORS
import os
import json
import threading
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from matplotlib.style import context
from werkzeug.security import generate_password_hash, check_password_hash
from scan import scan_target
import re, socket
from subdomain import find_subdomains_and_crawl
from subdirectory import get_subdirectories
from ssl_cert import get_ssl_certificate_info
from Nikto_vuln_scan import run_nikto_scan
from comprehensive_scanner import run_comprehensive_scan
from prompt_normalizer import normalize_zap_and_recon_to_json, write_json, build_recon_from_models
from AI_analyzer import analyze_json_ai_only

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnZero.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS

# MongoDB connection for storing analyzed scan results
mongo_client = MongoClient('mongodb://localhost:27017/')
mongo_db = mongo_client['vulnzero_scans']
scans_collection = mongo_db['analyzed_scans']

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Target(db.Model):
    target_id = db.Column(db.Integer, primary_key=True)
    target_name = db.Column(db.String(150), nullable=False)
    target_ip_address = db.Column(db.String(100), nullable=False)

class Target_ports(db.Model):
    port_id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('target.target_id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    port_service = db.Column(db.String(100), nullable= True)
    port_service_version = db.Column(db.String(100), nullable=True)

class Vulnerability(db.Model):
    vulnerability_id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('target.target_id'), nullable=False)
    port_id = db.Column(db.Integer, db.ForeignKey('target_ports.port_id'), nullable=True)
    vulnerability_name = db.Column(db.String(150), nullable=False)
    vulnerability_description = db.Column(db.Text, nullable=True)
    vulnerability_severity = db.Column(db.String(50), nullable=True)
    vulnerability_remediation = db.Column(db.Text, nullable=True)

class Subdomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('target.target_id'), nullable=False)
    subdomain = db.Column(db.String(255), nullable=True)

class Subdirectory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('target.target_id'), nullable=False)
    subdirectory = db.Column(db.String(255), nullable=True)

class SSLCertificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('target.target_id'), nullable=False)
    subject = db.Column(db.String(255), nullable=True)
    issuer = db.Column(db.String(255), nullable=True)
    not_before = db.Column(db.String(100), nullable=True)
    not_after = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(100), nullable=True)
    error = db.Column(db.Text, nullable=True)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/test', methods=['GET', 'POST', 'OPTIONS'])
def test():
    """Test endpoint to verify server is working"""
    if request.method == 'OPTIONS':
        return '', 200
    return jsonify({
        'status': 'success',
        'method': request.method,
        'message': 'Server is working!'
    }), 200

@app.route('/templates/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json(force=True)
        except Exception as e:
            return jsonify({'status': 'false', 'message': f'Invalid JSON: {str(e)}'}), 400
        
        if not data:
            return jsonify({'status': 'false', 'message': 'No data provided'}), 400
            
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({'status': 'false', 'message': 'All fields are required!'}), 400
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'status': 'false', 'message': 'Username or email already exists!'}), 400
        if len(password) < 6:
            return jsonify({'status': 'false', 'message': 'Password must be at least 6 characters long!'}), 400
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'status': 'true', 'message': 'User registered successfully!'}), 201
    return render_template('register.html')



@app.route('/templates/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json(force=True)
        except Exception as e:
            return jsonify({'status': 'false', 'message': f'Invalid JSON: {str(e)}'}), 400
        
        if not data:
            return jsonify({'status': 'false', 'message': 'No data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'status': 'false', 'message': 'Invalid username or password!'}), 401
        login_user(user)
        return jsonify({'status': 'true', 'message': 'Logged in successfully!'}), 200
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))



@app.route('/templates/dashboard', methods=['GET'])
@login_required
def dashboard():
    if not current_user or not hasattr(current_user, 'username'):
        return redirect(url_for('login'))
    username = current_user.username
    return render_template('dashboard.html', username=username)


@app.route('/dashboard/targets', methods=['POST'])
#@login_required
def input_target():
    #if not current_user or not hasattr(current_user, 'id'):
     #   return jsonify({'status': 'false', 'message': 'User not authenticated!'}), 401
    
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({'status': 'false', 'message': f'Invalid JSON: {str(e)}'}), 400
    
    if not data:
        return jsonify({'status': 'false', 'message': 'No data provided'}), 400
    target = data.get('target')
    analyze_flag = True
    mode = (data.get('mode') or 'blue').lower()
    
    
    

    if not target:
        return jsonify({'status': 'false', 'message': 'Target name is required!'}), 400

    if re.search(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}+\.[0-9]{1,3}+$', target):
        ipaddress = target
        try:
            hostname = socket.gethostbyaddr(ipaddress)[0]
        except socket.herror:
            hostname = 'null'



    elif re.search(r'^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$', target):
        hostname = target
        try:
            ipaddress = socket.gethostbyname(hostname)
        except socket.gaierror:
            return jsonify({'status': 'false', 'message': 'Unable to resolve hostname!'}), 400
        
    elif re.search(r'^https?://', target):
        target_url = target

        try:
            hostname = re.sub(r'^https?://', '', target).split('/')[0]
            ipaddress = socket.gethostbyname(hostname)
        except socket.gaierror:
            return jsonify({'status': 'false', 'message': 'Unable to resolve hostname from URL!'}), 400

    else: 
        return jsonify({'status': 'false', 'message': 'Invalid target format!'}), 400
    
    new_target= Target(target_name=hostname, target_ip_address=ipaddress)
    db.session.add(new_target)
    db.session.commit()

    open_ports = scan_target(ipaddress, '1-1024')
    if not open_ports:
        return jsonify({'status': 'false', 'message': 'No open ports found or target is unreachable!'}), 400

    save_target_port_to_db(new_target.target_id, open_ports)
    cert_info = get_ssl_certificate_info(ipaddress)
    save_ssl_certificate_to_db(new_target.target_id, cert_info)

    # Run subdomain and subdirectory discovery
    subdomains = []
    subdirectories = []
    
    # Subdomain discovery
    try:
        subdomains, subdomain_error = find_subdomains_and_crawl(hostname)
        if not subdomain_error and subdomains:
            for sub in subdomains:
                if not Subdomain.query.filter_by(target_id=new_target.target_id, subdomain=sub).first():
                    db.session.add(Subdomain(target_id=new_target.target_id, subdomain=sub))
            db.session.commit()
    except Exception:
        subdomains = []

    # Subdirectory discovery
    try:
        subdirectories, subdir_error = get_subdirectories(hostname)
        if not subdir_error and subdirectories:
            for subdir in subdirectories:
                if not Subdirectory.query.filter_by(target_id=new_target.target_id, subdirectory=subdir).first():
                    db.session.add(Subdirectory(target_id=new_target.target_id, subdirectory=subdir))
            db.session.commit()
    except Exception:
        subdirectories = []

    # Automated vulnerability scanning and normalization (JSON)
    # Build a basic URL guess for Nikto: prefer https if port 443 is open
    
    scheme = 'http'
    target_url_basic = f"{scheme}://{ipaddress}"

    # Threading variables to store results
    nikto_alerts = []
    comprehensive_results = None
    nikto_error = None
    comp_error = None

    def run_nikto_scan_wrapper():
        nonlocal nikto_alerts, nikto_error
        try:
            if target_url:
                nikto_alerts = run_nikto_scan(target_url)
            else:
                nikto_alerts = run_nikto_scan(target_url_basic)
        except Exception as e:
            nikto_error = str(e)
            nikto_alerts = []

    def run_comprehensive_scan_thread():
        nonlocal comprehensive_results, comp_error
        try:
            if target_url:
                comprehensive_results = run_comprehensive_scan(target_url)
            else:
                comprehensive_results = run_comprehensive_scan(target_url_basic)
        except Exception as e:
            comp_error = str(e)
            comprehensive_results = None

    # Start both scanners in parallel
    nikto_thread = threading.Thread(target=run_nikto_scan_wrapper)
    comp_thread = threading.Thread(target=run_comprehensive_scan_thread)
    
    #nikto_thread.start()
    comp_thread.start()
    
    # Wait for both to complete
    #nikto_thread.join()
    comp_thread.join()

    # Collect reconnaissance data from DB to embed
    recon = build_recon_from_models(
        open_ports_rows=Target_ports.query.filter_by(target_id=new_target.target_id).all(),
        subdomain_rows=Subdomain.query.filter_by(target_id=new_target.target_id).all(),
        subdirectory_rows=Subdirectory.query.filter_by(target_id=new_target.target_id).all(),
        ssl_cert_rows=SSLCertificate.query.filter_by(target_id=new_target.target_id).all(),
        hostname=hostname,
        ipaddress=ipaddress,
    )

    # Merge Nikto and comprehensive scanner results
    all_vulnerabilities = list(nikto_alerts) if nikto_alerts else []
    if comprehensive_results and 'vulnerabilities' in comprehensive_results:
        # Convert comprehensive scanner results to Nikto-like format
        for vuln in comprehensive_results['vulnerabilities']:
            all_vulnerabilities.append({
                'source': 'comprehensive_scanner',
                'alert': vuln.get('type', 'Unknown'),
                'title': vuln.get('type', 'Unknown'),
                'description': vuln.get('description', ''),
                'severity': vuln.get('severity', 'Low').lower(),
                'url': vuln.get('url', ''),
                'param': vuln.get('param', ''),
                'evidence': vuln.get('evidence', ''),
                'remediation': vuln.get('recommendation', ''),
            })

    normalized = normalize_zap_and_recon_to_json(all_vulnerabilities, recon)
    json_out_path = './scans/combined.json'
    try:
        write_json(normalized, json_out_path)
    except Exception:
        pass

    response_payload = {
        'status': 'true',
        'message': 'Target added and comprehensive scan completed.',
        'target': hostname,
        'ip': ipaddress,
        'subdomains_found': len(subdomains),
        'subdirectories_found': len(subdirectories),
        'nikto_alerts_count': len(nikto_alerts),
        'comprehensive_vulns_count': len(comprehensive_results.get('vulnerabilities', [])) if comprehensive_results else 0,
        'total_vulnerabilities': len(all_vulnerabilities),
        'nikto_error': nikto_error,
        'comprehensive_error': comp_error,
        'normalized_json_path': json_out_path,
        'normalized_combined_vuln': normalized
    }

    if analyze_flag:
        try:
            analysis = analyze_json_ai_only(normalized, mode=mode)
            response_payload['analysis'] = analysis
        except Exception as e:
            response_payload['analysis_error'] = str(e)

    # Save analyzed results to MongoDB if AI analysis was performed
    if analyze_flag and analysis and current_user and hasattr(current_user, 'id'):
        save_analyzed_scan_to_mongodb(
            target_id=new_target.target_id,
            target_name=hostname,
            target_ip=ipaddress,
            normalized_data=normalized,
            ai_analysis=analysis,
            mode=mode,
            nikto_alerts_count=len(nikto_alerts),
            comprehensive_vulns_count=len(comprehensive_results.get('vulnerabilities', [])) if comprehensive_results else 0,
            total_vulnerabilities=len(all_vulnerabilities),
            user_id=current_user.id,
            nikto_error=nikto_error,
            comprehensive_error=comp_error
        )

    return jsonify(response_payload), 201



def save_target_port_to_db(target_id, open_ports):
    for port_info in open_ports:
        port_number = port_info['port']
        port_service = port_info['service']
        port_service_version = port_info['version']

        new_port = Target_ports(
            target_id=target_id,
            port_number=port_number,
            port_service=port_service,
            port_service_version=port_service_version
        )
        db.session.add(new_port)
    db.session.commit()

def save_ssl_certificate_to_db(target_id, cert_info):
    """
    Stores SSL certificate information in the SSLCertificate table.
    cert_info should be a dictionary as returned by get_ssl_certificate_info.
    """
    ssl_cert = SSLCertificate(
        target_id=target_id,
        subject=str(cert_info.get('subject')),
        issuer=str(cert_info.get('issuer')),
        not_before=str(cert_info.get('not_before')),
        not_after=str(cert_info.get('not_after')),
        status=cert_info.get('status'),
        error=cert_info.get('error')
    )
    db.session.add(ssl_cert)
    db.session.commit()

def save_analyzed_scan_to_mongodb(target_id, target_name, target_ip, normalized_data, ai_analysis, mode, 
                                 nikto_alerts_count, comprehensive_vulns_count, total_vulnerabilities, 
                                 user_id, nikto_error=None, comprehensive_error=None):
    """
    Save analyzed scan results to MongoDB with user isolation
    """
    scan_document = {
        'user_id': user_id,  # Add user_id for isolation
        'target_id': target_id,
        'target_name': target_name,
        'target_ip': target_ip,
        'scan_timestamp': datetime.utcnow(),
        'mode': mode,
        'nikto_alerts_count': nikto_alerts_count,
        'comprehensive_vulns_count': comprehensive_vulns_count,
        'total_vulnerabilities': total_vulnerabilities,
        'normalized_data': normalized_data,
        'ai_analysis': ai_analysis,
        'nikto_error': nikto_error,
        'comprehensive_error': comprehensive_error,
        'status': 'completed'
    }
    
    result = scans_collection.insert_one(scan_document)
    return result.inserted_id

def get_analyzed_scans_from_mongodb(user_id, target_id=None, limit=50):
    """
    Retrieve analyzed scan results from MongoDB for specific user
    """
    query = {'user_id': user_id}  # Always filter by user_id
    if target_id:
        query['target_id'] = target_id
    
    scans = list(scans_collection.find(query).sort('scan_timestamp', -1).limit(limit))
    
    # Convert ObjectId to string for JSON serialization
    for scan in scans:
        scan['_id'] = str(scan['_id'])
        scan['scan_timestamp'] = scan['scan_timestamp'].isoformat()
    
    return scans




@app.route('/dashboard/analyzed-scans', methods=['GET'])
@login_required
def get_analyzed_scans():
    """Get analyzed scan results from MongoDB for current user only with time, target, and mode details"""
    if not current_user or not hasattr(current_user, 'id'):
        return jsonify({'error': 'User not authenticated'}), 401
    
    target_id = request.args.get('target_id', type=int)
    limit = request.args.get('limit', 50, type=int)
    
    scans = get_analyzed_scans_from_mongodb(user_id=current_user.id, target_id=target_id, limit=limit)
    
    # Format scans with key details: time, target, mode
    result = []
    for scan in scans:
        scan_entry = {
            'scan_id': str(scan.get('_id', '')),
            'scan_timestamp': scan.get('scan_timestamp'),
            'target_name': scan.get('target_name', 'Unknown'),
            'target_ip': scan.get('target_ip', 'Unknown'),
            'target_id': scan.get('target_id'),
            'mode': scan.get('mode', 'unknown'),
            'status': scan.get('status', 'unknown'),
            'total_vulnerabilities': scan.get('total_vulnerabilities', 0),
            'nikto_alerts_count': scan.get('nikto_alerts_count', 0),
            'comprehensive_vulns_count': scan.get('comprehensive_vulns_count', 0)
        }
        result.append(scan_entry)
    
    # Sort by most recent scan timestamp (newest first)
    result.sort(key=lambda x: x.get('scan_timestamp', ''), reverse=True)
    
    return jsonify({
        'scans': result,
        'total_scans': len(result)
    }), 200

@app.route('/dashboard/analyzed-scans/<scan_id>', methods=['GET'])
@login_required
def get_analyzed_scan_details(scan_id):
    """Get AI analysis for a specific scan by MongoDB _id (user's scans only)"""
    if not current_user or not hasattr(current_user, 'id'):
        return jsonify({'error': 'User not authenticated'}), 401
    
    try:
        from bson import ObjectId
        scan = scans_collection.find_one(
            {
                '_id': ObjectId(scan_id),
                'user_id': current_user.id  # Ensure user can only access their own scans
            },
            {'ai_analysis': 1}  # Only fetch the ai_analysis field
        )
        
        if not scan:
            return jsonify({'error': 'Scan not found or access denied'}), 404
        
        # Return only the AI analysis
        ai_analysis = scan.get('ai_analysis', {})
        
        if not ai_analysis:
            return jsonify({'error': 'AI analysis not available for this scan'}), 404
        
        return jsonify(ai_analysis), 200
    except ValueError as e:
        return jsonify({'error': f'Invalid scan ID format: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Error retrieving scan: {str(e)}'}), 500





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)