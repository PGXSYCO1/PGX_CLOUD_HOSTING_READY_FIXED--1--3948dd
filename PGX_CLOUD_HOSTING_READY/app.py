from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import json
import os
import subprocess
import random
import string
import uuid
import secrets
from urllib.parse import urlencode, urlparse, unquote, quote
from datetime import datetime, timedelta
import sys
import shutil
import re
import sqlite3
import threading
import time
import zipfile
try:
    import psutil
except ImportError:  # Optional on restricted shared-hosting plans
    psutil = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

app = Flask(__name__)
# Honor the reverse proxy's public scheme/host when deployed behind Web Deploy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
def get_secret_key():
    env_key = os.environ.get('PGX_SECRET_KEY')
    if env_key:
        return env_key
    key_path = os.path.join(BASE_DIR, '.pgx_secret_key')
    try:
        if os.path.exists(key_path):
            with open(key_path, 'r', encoding='utf-8') as fh:
                return fh.read().strip()
        key = uuid.uuid4().hex + uuid.uuid4().hex
        with open(key_path, 'w', encoding='utf-8') as fh:
            fh.write(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        return uuid.uuid4().hex + uuid.uuid4().hex

app.secret_key = get_secret_key()
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('PGX_COOKIE_SECURE', '0').lower() in ('1', 'true', 'yes')


@app.before_request
def pgx_authorization_guard():
    path = request.path
    if not path.startswith('/api/'):
        return None

    # Admin bypass is valid only when the live database still marks this account
    # as an enabled administrator. A stale/forged session role is not enough.
    users = load_users()
    session_user = session.get('user')
    admin_record = users.get(session_user, {}) if session_user else {}
    is_active_admin = (
        session.get('role') == 'admin'
        and isinstance(admin_record, dict)
        and admin_record.get('role') == 'admin'
        and not admin_record.get('disabled')
    )
    if is_active_admin:
        return None

    # Legacy provisioning endpoint creates accounts/projects via query-string
    # credentials. Keep it unavailable to public visitors; admins can still use it.
    if path == '/api/create':
        return jsonify({'status': 'error', 'message': 'Admin login required.'}), 403
    server_id = (request.view_args or {}).get('server_id')
    if not server_id and path == '/api/command':
        payload = request.get_json(silent=True) or {}
        server_id = payload.get('server_id')
    if not server_id or 'user' not in session or session.get('role') != 'user':
        return jsonify({'error': 'Please login to the project first.'}), 403
    server, owner = get_server_by_id(str(server_id))
    user_record = users.get(session_user, {}) if session_user else {}
    if (not server or owner != session_user
            or not isinstance(user_record, dict)
            or user_record.get('disabled')
            or session.get('current_server_id') != str(server_id)):
        return jsonify({'error': 'You do not have access to this project.'}), 403
    return None

USERS_FILE = os.path.join(BASE_DIR, 'users.json')
GOOGLE_ACCOUNTS_FILE = os.path.join(BASE_DIR, 'google_accounts.json')
FREE_CLAIM_LOCK = threading.Lock()
BOTS_DIR = os.path.join(BASE_DIR, 'bots')
CPU_HISTORY = {}
CRASH_COUNT = {}
NET_STATS = {}

os.makedirs(BOTS_DIR, exist_ok=True)

# ============================================
# রেট লিমিট
# ============================================

class RateLimiter:
    def check_rate(self, server_id, limit_percent):
        if server_id not in CPU_HISTORY:
            CPU_HISTORY[server_id] = []
        users = load_users()
        server = None
        for uname, data in users.items():
            if data.get('role') == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    server = s
                    break
        if not server or server.get('status') != 'running':
            return False, 0
        pid = server.get('pid')
        if not pid: return False, 0
        try:
            if psutil is None:
                return False, 0
            proc = psutil.Process(pid)
            cpu = proc.cpu_percent(interval=1)
            now = time.time()
            CPU_HISTORY[server_id].append({'time': now, 'cpu': cpu})
            CPU_HISTORY[server_id] = [h for h in CPU_HISTORY[server_id] if now - h['time'] < 30]
            recent = [h['cpu'] for h in CPU_HISTORY[server_id] if now - h['time'] < 10]
            if recent:
                avg_cpu = sum(recent) / len(recent)
                if avg_cpu > limit_percent:
                    return True, avg_cpu
        except: pass
        return False, 0

rate_limiter = RateLimiter()

# ============================================
# অটো-রিস্টার্ট
# ============================================

def should_auto_restart(server_id):
    if server_id not in CRASH_COUNT:
        CRASH_COUNT[server_id] = {'count': 0, 'last_crash': time.time()}
    crash_info = CRASH_COUNT[server_id]
    if time.time() - crash_info['last_crash'] < 60:
        if crash_info['count'] >= 3:
            return False
    else:
        crash_info['count'] = 0
    crash_info['count'] += 1
    crash_info['last_crash'] = time.time()
    return True

# ============================================
# হেল্পার
# ============================================

def generate_random_password(length=10):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def load_users():
    """Read account data without silently migrating, renaming, or rewriting it."""
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            app.logger.error('users.json root must be a JSON object; refusing to overwrite it')
            return {}
        return data
    except (json.JSONDecodeError, OSError) as exc:
        app.logger.error('Could not read users.json; original file left untouched: %s', exc)
        raise RuntimeError('users.json is unreadable; refusing to modify account data') from exc


def save_users(data):
    """Atomically replace users.json so an interrupted write cannot truncate it."""
    if not isinstance(data, dict):
        raise ValueError('User database must be an object')
    temp_path = USERS_FILE + '.tmp'
    with open(temp_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, USERS_FILE)


def verify_account_password(account, supplied_password):
    """Verify current hashes and legacy plaintext records without breaking old accounts."""
    if not isinstance(account, dict) or not isinstance(supplied_password, str):
        return False
    stored_hash = account.get('password_hash')
    if stored_hash:
        try:
            return check_password_hash(stored_hash, supplied_password)
        except (TypeError, ValueError):
            return False
    legacy = account.get('password')
    return isinstance(legacy, str) and secrets.compare_digest(legacy, supplied_password)


def normalize_username(value):
    return str(value or '').strip()


def load_google_accounts():
    try:
        with open(GOOGLE_ACCOUNTS_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_google_accounts(data):
    temp_path = GOOGLE_ACCOUNTS_FILE + '.tmp'
    with open(temp_path, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(temp_path, GOOGLE_ACCOUNTS_FILE)


def google_oauth_configured():
    return bool(os.environ.get('GOOGLE_CLIENT_ID') and os.environ.get('GOOGLE_CLIENT_SECRET'))


def get_csrf_token():
    token = session.get('pgx_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['pgx_csrf_token'] = token
    return token


def make_google_username(email, users):
    base = re.sub(r'[^a-zA-Z0-9_]', '_', email.split('@', 1)[0]).strip('_') or 'google_user'
    base = base[:24]
    candidate = base
    suffix = 1
    while candidate in users and (users[candidate].get('email', '').lower() != email.lower() or users[candidate].get('role') == 'admin'):
        suffix += 1
        candidate = f'{base[:19]}_{suffix}'
    return candidate


def create_user_project(username, account, days=3):
    '''Provision the existing panel's standard free project for a signed-in user.'''
    server_id = str(uuid.uuid4())[:8]
    expiry_date = datetime.now() + timedelta(days=days)
    server_dir = get_server_dir(server_id)
    create_default_files(server_dir)
    server = {
        'server_id': server_id,
        'link': server_id,
        'login_url': f'/{server_id}/login',
        'dashboard_url': f'/{server_id}/home',
        'full_link': f'/{server_id}/home',
        'type': 'python',
        'ram': '1GB',
        'disk': '1GB',
        'status': 'stopped',
        'pid': None,
        'created': str(datetime.now()),
        'expiry': str(expiry_date),
        'main_file': 'main.py',
        'requirements_file': 'requirements.txt',
        'cpu_limit': 30,
        'rate_limit_exceeded': False,
        'stopped_by_user': False,
        'plan': 'free'
    }
    account.setdefault('servers', []).append(server)
    return server

def get_server_dir(server_id):
    server_dir = os.path.join(BOTS_DIR, server_id)
    os.makedirs(server_dir, exist_ok=True)
    return server_dir

def safe_project_path(server_id, relative=''):
    base = os.path.realpath(get_server_dir(server_id))
    candidate = os.path.realpath(os.path.join(base, str(relative or '')))
    try:
        if os.path.commonpath([base, candidate]) != base:
            raise ValueError('Invalid project path')
    except ValueError:
        raise ValueError('Invalid project path')
    return candidate

def check_server_valid(server_id):
    users = load_users()
    for uname, data in users.items():
        if data.get('role') == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                expiry = s.get('expiry', '')
                if expiry:
                    try:
                        exp_date = datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S.%f')
                        if datetime.now() > exp_date:
                            return False, "expired"
                    except: pass
                return True, s
    return False, "deleted"

def get_server_by_id(server_id):
    users = load_users()
    for uname, data in users.items():
        if data.get('role') == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                return s, uname
    return None, None

def create_default_files(server_dir):
    main_py = os.path.join(server_dir, 'main.py')
    if not os.path.exists(main_py):
        with open(main_py, 'w', encoding='utf-8') as f:
            f.write('''# PGX CLOUD - Default Bot
import time

print("=" * 40)
print("Bot is running on PGX CLOUD")
print("Server is ready!")
print("=" * 40)

counter = 0
while True:
    counter += 1
    print(f"[{time.strftime('%H:%M:%S')}] Heartbeat #{counter} | Server active")
    time.sleep(10)
''')
    
    req_file = os.path.join(server_dir, 'requirements.txt')
    if not os.path.exists(req_file):
        with open(req_file, 'w', encoding='utf-8') as f:
            f.write('# Add your pip packages here\n')


def ram_limit_mb(value):
    raw = str(value or '512MB').strip().upper()
    match = re.fullmatch(r'(\d+)(MB|GB)', raw)
    if not match:
        return 512
    amount = int(match.group(1))
    return amount * 1024 if match.group(2) == 'GB' else amount

# ============================================
# বট রান
# ============================================

def run_bot(server_id, main_file='main.py', requirements_file='requirements.txt'):
    server_dir = get_server_dir(server_id)
    try:
        main_path = safe_project_path(server_id, main_file)
    except ValueError:
        return None, 'Invalid startup file path'
    log_file = os.path.join(server_dir, 'output.log')
    python_exe = sys.executable
    
    def log(msg):
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"{msg}\n")
                f.flush()
        except: pass
    
    if not os.path.exists(main_path):
        return None, f"ERROR: {main_file} not found!"
    
    if os.path.exists(log_file):
        try: os.remove(log_file)
        except: open(log_file, 'w').close()
    
    ts = lambda: datetime.now().strftime('%I:%M:%S %p')
    
    server, _ = get_server_by_id(server_id)
    cpu_limit = server.get('cpu_limit', 80) if server else 80
    log(f"[{ts()}] Checking rate limit...")
    log(f"[{ts()}] Rate limit: {cpu_limit}%")
    log("")
    
    if requirements_file and requirements_file.strip():
        try:
            req_path = safe_project_path(server_id, requirements_file.strip())
        except ValueError:
            return None, 'Invalid requirements file path'
        log(f"[{ts()}] Run: pip install -r {requirements_file}")
        log("")
        
        if os.path.exists(req_path):
            with open(req_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
            
            if lines:
                try:
                    proc = subprocess.Popen(
                        [python_exe, '-m', 'pip', 'install', '-r', os.path.abspath(req_path), '--disable-pip-version-check'],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1, universal_newlines=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    
                    for line in iter(proc.stdout.readline, ''):
                        if line.strip():
                            log(f"[{ts()}] {line.rstrip()}")
                    
                    proc.wait()
                    log("")
                    
                    if proc.returncode != 0:
                        log(f"[{ts()}] Some packages failed to install")
                    else:
                        log(f"[{ts()}] Requirements installation complete!")
                except Exception as e:
                    log(f"[{ts()}] pip error: {str(e)}")
            else:
                log(f"[{ts()}] {requirements_file} is empty, skipping...")
        else:
            log(f"[{ts()}] {requirements_file} not found, skipping...")
    else:
        log(f"[{ts()}] No requirements file set, skipping...")
    
    log("")
    log(f"[{ts()}] Run: python {main_file}")
    log(f"[{ts()}] Python {sys.version.split()[0]}")
    log("")
    
    try:
        main_path_abs = os.path.abspath(main_path)
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUNBUFFERED'] = '1'
        
        proc = subprocess.Popen(
            [python_exe, main_path_abs],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=server_dir,
            text=True, encoding='utf-8', errors='replace',
            bufsize=1, env=env, universal_newlines=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        
        log(f"[{ts()}] Server marked as running")
        log(f"[{ts()}] PID: {proc.pid}")
        log("")
        
        def rate_monitor():
            while proc.poll() is None:
                time.sleep(5)
                exceeded, avg_cpu = rate_limiter.check_rate(server_id, cpu_limit)
                server_now, _ = get_server_by_id(server_id)
                limit_mb = ram_limit_mb(server_now.get('ram', '512MB') if server_now else '512MB')
                try:
                    used_mb = psutil.Process(proc.pid).memory_info().rss / (1024 * 1024)
                except Exception:
                    used_mb = 0
                ram_exceeded = bool(used_mb and used_mb > limit_mb)
                if exceeded or ram_exceeded:
                    if exceeded:
                        log(f"[{datetime.now().strftime('%I:%M:%S %p')}] CPU limit exceeded: {avg_cpu:.1f}% > {cpu_limit}%")
                    if ram_exceeded:
                        log(f"[{datetime.now().strftime('%I:%M:%S %p')}] RAM limit exceeded: {used_mb:.1f} MB > {limit_mb} MB")
                    proc.terminate()
                    time.sleep(2)
                    if proc.poll() is None: proc.kill()
                    users = load_users()
                    for uname, data in users.items():
                        if data.get('role') == 'admin': continue
                        servers = data.get('servers', [])
                        if not isinstance(servers, list): continue
                        for srv in servers:
                            if isinstance(srv, dict) and srv.get('server_id') == server_id:
                                srv['status'] = 'stopped'
                                srv['pid'] = None
                                srv['rate_limit_exceeded'] = bool(exceeded)
                                srv['ram_limit_exceeded'] = bool(ram_exceeded)
                                srv['stopped_by_user'] = False
                                save_users(users)
                                break
                    break
        
        threading.Thread(target=rate_monitor, daemon=True).start()
        
        def stream_output():
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    for line in iter(proc.stdout.readline, ''):
                        if line:
                            line = line.rstrip('\n\r')
                            if line:
                                f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] {line}\n")
                                f.flush()
            except: pass
        
        threading.Thread(target=stream_output, daemon=True).start()
        
        return proc.pid, None
        
    except Exception as e:
        log(f"[{ts()}] Error: {str(e)}")
        return None, str(e)

def stop_bot_process(pid):
    try:
        if sys.platform == 'win32':
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
        else:
            os.kill(pid, 15)
        return True
    except: return False

def monitor_bot(server_id, pid):
    while True:
        try:
            if sys.platform == 'win32':
                result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], capture_output=True, text=True)
                if str(pid) not in result.stdout:
                    break
            else:
                try: os.kill(pid, 0)
                except: break
        except: break
        time.sleep(5)
    
    server, _ = get_server_by_id(server_id)
    if not server: return
    if server.get('stopped_by_user'): return
    if server.get('rate_limit_exceeded'): return
    
    if should_auto_restart(server_id):
        time.sleep(3)
        new_pid, error = run_bot(server_id, server.get('main_file', 'main.py'), 
                                 server.get('requirements_file', 'requirements.txt'))
        if new_pid:
            users = load_users()
            for uname, data in users.items():
                if data.get('role') == 'admin': continue
                servers = data.get('servers', [])
                if not isinstance(servers, list): continue
                for s in servers:
                    if isinstance(s, dict) and s.get('server_id') == server_id:
                        s['status'] = 'running'
                        s['pid'] = new_pid
                        s['started_at'] = str(datetime.now())
                        s['rate_limit_exceeded'] = False
                        s['stopped_by_user'] = False
                        save_users(users)
                        break
            threading.Thread(target=monitor_bot, args=(server_id, new_pid), daemon=True).start()
    else:
        users = load_users()
        for uname, data in users.items():
            if data.get('role') == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    s['status'] = 'stopped'
                    s['pid'] = None
                    save_users(users)
                    return

def get_process_stats(pid):
    try:
        proc = psutil.Process(pid)
        cpu = proc.cpu_percent(interval=0.5)
        mem = proc.memory_info()
        ram = mem.rss / (1024 * 1024)
        return {
            'cpu_percent': round(cpu, 1),
            'ram_mb': round(ram, 1),
            'ram_display': f"{ram:.1f} MB" if ram < 1024 else f"{ram/1024:.1f} GB",
        }
    except:
        return {'cpu_percent': 0, 'ram_mb': 0, 'ram_display': '0 MB'}

def get_network_stats(psutil_pid):
    try:
        proc = psutil.Process(psutil_pid)
        io = proc.io_counters()
        if io:
            read_kb = io.read_bytes / 1024
            write_kb = io.write_bytes / 1024
            return format_bytes(read_kb), format_bytes(write_kb)
    except: pass
    return "0 KB", "0 KB"

def format_bytes(kb):
    if kb < 1024: return f"{kb:.1f} KB"
    mb = kb / 1024
    if mb < 1024: return f"{mb:.1f} MB"
    gb = mb / 1024
    return f"{gb:.2f} GB"

# ============================================
# 🔥 পাবলিক API - সার্ভার তৈরি
# ============================================

@app.route('/api/create', methods=['GET'])
def api_create_server():
    username = request.args.get('username', '').strip()
    password = request.args.get('password', '').strip()
    server_type = request.args.get('type', 'python').strip()
    ram = request.args.get('ram', '1GB').strip()
    disk = request.args.get('disk', '1GB').strip()
    cpu_limit = int(request.args.get('cpu', '30'))
    days = int(request.args.get('days', '3'))
    
    if not password:
        password = generate_random_password(10)
    
    if not username:
        username = f"PGX_USER{random.randint(10000, 99999)}"
    
    if len(username) < 3:
        return jsonify({'status': 'error', 'message': 'Username must be at least 3 characters!'}), 400
    
    if len(password) < 4:
        return jsonify({'status': 'error', 'message': 'Password must be at least 4 characters!'}), 400
    
    if cpu_limit < 10 or cpu_limit > 100:
        return jsonify({'status': 'error', 'message': 'CPU limit must be between 10 and 100!'}), 400
    
    if days < 1 or days > 365:
        return jsonify({'status': 'error', 'message': 'Days must be between 1 and 365!'}), 400
    
    users = load_users()
    
    if username in users:
        return jsonify({'status': 'error', 'message': f"Username '{username}' already exists!"}), 400
    
    server_id = str(uuid.uuid4())[:8]
    expiry_date = datetime.now() + timedelta(days=days)
    
    create_default_files(get_server_dir(server_id))
    
    full_url = request.url_root.rstrip('/') + f'/{server_id}/login'
    
    new_server = {
        'server_id': server_id,
        'login_url': f"/{server_id}/login",
        'dashboard_url': f"/{server_id}/home",
        'full_link': full_url,
        'type': server_type,
        'ram': ram, 'disk': disk,
        'status': 'stopped', 'pid': None,
        'created': str(datetime.now()),
        'expiry': str(expiry_date),
        'main_file': 'main.py',
        'requirements_file': 'requirements.txt',
        'cpu_limit': cpu_limit,
        'rate_limit_exceeded': False,
        'stopped_by_user': False
    }
    
    users[username] = {'password': password, 'role': 'user', 'servers': [new_server]}
    save_users(users)
    
    return jsonify({
        'status': 'success',
        'message': 'Panel created successfully!',
        'username': username,
        'password': password,
        'server_type': server_type,
        'ram': ram,
        'disk': disk,
        'cpu_limit': cpu_limit,
        'validity': f'{days} days',
        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
        'full_url': full_url,
        'server_id': server_id
    }), 200

# ============================================
# রাউটস
# ============================================

@app.route('/health')
@app.route('/healthz')
def health_check():
    return jsonify({'ok': True, 'service': 'PGX CLOUD', 'status': 'running'}), 200

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = normalize_username(request.form.get('username'))
        password = request.form.get('password', '')
        users = load_users()
        account = users.get(username, {})
        if account and verify_account_password(account, password) and not account.get('disabled'):
            session.clear()
            session['user'] = username
            session['role'] = account.get('role', 'user')
            # Upgrade legacy plaintext passwords only after successful authentication.
            if account.get('password') and not account.get('password_hash'):
                account['password_hash'] = generate_password_hash(account.pop('password'))
                save_users(users)
            if account.get('role') == 'admin':
                return redirect(url_for('admin_dashboard'))
            next_action = request.form.get('next', 'account')
            if next_action == 'claim':
                return redirect(url_for('free_claim'))
            return redirect(url_for('user_account'))
        return render_template('login.html', error='Invalid username or password.', google_enabled=google_oauth_configured(), server_id=None, next_action=request.args.get('next', 'account'))
    next_action = request.args.get('next', 'account')
    if next_action not in ('account', 'claim'):
        next_action = 'account'
    return render_template('login.html', error=None, google_enabled=google_oauth_configured(), server_id=None, next_action=next_action)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = normalize_username(request.form.get('username'))
        password = request.form.get('password', '')
        if not re.fullmatch(r'[A-Za-z0-9_]{3,24}', username):
            return render_template('register.html', error='Username must be 3–24 characters (letters, numbers, underscore).', google_enabled=google_oauth_configured())
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters.', google_enabled=google_oauth_configured())
        users = load_users()
        if username in users:
            return render_template('register.html', error='Unable to create this account. Try another username.', google_enabled=google_oauth_configured())
        users[username] = {'role': 'user', 'password_hash': generate_password_hash(password), 'servers': [], 'created_at': datetime.now().isoformat(timespec='seconds')}
        save_users(users)
        session.clear()
        session['user'] = username
        session['role'] = 'user'
        return redirect(url_for('user_account'))
    return render_template('register.html', error=None, google_enabled=google_oauth_configured())

@app.route('/<server_id>/login', methods=['GET', 'POST'])
def server_login(server_id):
    valid, result = check_server_valid(server_id)
    if not valid:
        return render_template('error.html', error_type=result if result else "deleted", server_link=server_id)
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        users = load_users()
        for uname, data in users.items():
            if data.get('role') == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    if username == uname and verify_account_password(data, password) and not data.get('disabled'):
                        session['user'] = uname
                        session['role'] = 'user'
                        session['current_server_id'] = server_id
                        return redirect(url_for('server_home', server_id=server_id))
                    else:
                        return render_template('login.html', error="Invalid credentials!", google_enabled=google_oauth_configured(), server_id=server_id)
        return render_template('login.html', error="Invalid login!", google_enabled=google_oauth_configured(), server_id=server_id)
    return render_template('login.html', error=None, google_enabled=google_oauth_configured(), server_id=server_id)

@app.route('/<server_id>/home')
def server_home(server_id):
    if 'user' not in session or session.get('role') != 'user':
        return redirect(url_for('server_login', server_id=server_id))
    if session.get('current_server_id') != server_id:
        session.clear()
        return redirect(url_for('server_login', server_id=server_id))
    
    valid, result = check_server_valid(server_id)
    if not valid:
        session.clear()
        return render_template('error.html', error_type=result if result else "deleted", server_link=server_id)
    
    return render_template('home.html', username=session['user'], current_server=result)

@app.route('/logout')
def logout():
    server_id = session.get('current_server_id')
    session.clear()
    if server_id:
        return redirect(url_for('server_login', server_id=server_id))
    return redirect(url_for('login'))

# ============================================
# GOOGLE LOGIN + USER ACCOUNT + INTERNAL FREE CLAIM
# ============================================

@app.route('/auth/google')
def auth_google_start():
    if not google_oauth_configured():
        return render_template('error.html', error_type='Google Login is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.', server_link=''), 503
    next_action = request.args.get('next', 'account')
    if next_action not in ('account', 'claim'):
        next_action = 'account'
    server_id = request.args.get('server_id', '').strip()
    if server_id:
        server, _owner = get_server_by_id(server_id)
        if not server:
            server_id = ''
    state = secrets.token_urlsafe(32)
    session['google_oauth_state'] = state
    session['google_oauth_next'] = next_action
    session['google_oauth_server_id'] = server_id
    redirect_uri = os.environ.get('GOOGLE_REDIRECT_URI') or url_for('auth_google_callback', _external=True)
    params = {
        'client_id': os.environ['GOOGLE_CLIENT_ID'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'prompt': 'select_account'
    }
    return redirect('https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params))


@app.route('/auth/google/callback')
def auth_google_callback():
    expected_state = session.pop('google_oauth_state', None)
    received_state = request.args.get('state', '')
    if not expected_state or not secrets.compare_digest(str(expected_state), str(received_state)):
        return render_template('error.html', error_type='Google login verification failed. Please try again.', server_link=''), 400
    if request.args.get('error'):
        return redirect(url_for('landing'))
    code = request.args.get('code', '')
    if not code or not google_oauth_configured():
        return render_template('error.html', error_type='Google login could not be completed.', server_link=''), 400
    redirect_uri = os.environ.get('GOOGLE_REDIRECT_URI') or url_for('auth_google_callback', _external=True)
    try:
        token_response = requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'code': code,
                'client_id': os.environ['GOOGLE_CLIENT_ID'],
                'client_secret': os.environ['GOOGLE_CLIENT_SECRET'],
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }, timeout=15
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        id_token = token_data.get('id_token')
        if not id_token:
            raise ValueError('Google did not return an ID token')
        verify_response = requests.get(
            'https://oauth2.googleapis.com/tokeninfo', params={'id_token': id_token}, timeout=15
        )
        verify_response.raise_for_status()
        profile = verify_response.json()
        if profile.get('aud') != os.environ['GOOGLE_CLIENT_ID']:
            raise ValueError('Google token audience mismatch')
        if str(profile.get('email_verified', '')).lower() != 'true':
            raise ValueError('Google email is not verified')
        if profile.get('iss') not in ('accounts.google.com', 'https://accounts.google.com'):
            raise ValueError('Google token issuer mismatch')
        if int(profile.get('exp', '0')) <= int(time.time()):
            raise ValueError('Google token has expired')
        email = str(profile.get('email', '')).strip().lower()
        google_sub = str(profile.get('sub', '')).strip()
        if not email or not google_sub or '@' not in email:
            raise ValueError('Google profile is incomplete')
    except Exception as exc:
        app.logger.warning('Google OAuth failed: %s', exc)
        return render_template('error.html', error_type='Google sign-in failed. Check OAuth configuration and try again.', server_link=''), 400

    users = load_users()
    username = None
    for name, record in users.items():
        if record.get('role') != 'admin' and (
            record.get('google_sub') == google_sub or str(record.get('email', '')).lower() == email
        ):
            username = name
            break
    if username is None:
        username = make_google_username(email, users)
        users[username] = {
            'role': 'user',
            'password_hash': generate_password_hash(secrets.token_urlsafe(32)),
            'servers': [],
            'email': email,
            'google_sub': google_sub,
            'auth_provider': 'google',
            'created_at': datetime.now().isoformat(timespec='seconds')
        }
    account = users[username]
    if account.get('role') == 'admin' or account.get('disabled'):
        return render_template('error.html', error_type='This account is not allowed to sign in.', server_link=''), 403
    account['email'] = email
    account['google_sub'] = google_sub
    account['auth_provider'] = 'google'
    account['google_name'] = profile.get('name', '')
    account['google_picture'] = profile.get('picture', '')
    account['last_login'] = datetime.now().isoformat(timespec='seconds')
    save_users(users)

    google_accounts = load_google_accounts()
    existing = google_accounts.get(google_sub, {})
    google_accounts[google_sub] = {
        'email': email,
        'username': username,
        'name': profile.get('name', ''),
        'picture': profile.get('picture', ''),
        'created_at': existing.get('created_at') or datetime.now().isoformat(timespec='seconds'),
        'last_login': datetime.now().isoformat(timespec='seconds'),
        'login_count': int(existing.get('login_count', 0)) + 1
    }
    save_google_accounts(google_accounts)

    next_action = session.pop('google_oauth_next', 'account')
    target_server = session.pop('google_oauth_server_id', '')
    session.clear()
    session['user'] = username
    session['role'] = 'user'
    if target_server:
        server, owner = get_server_by_id(target_server)
        if server and owner == username:
            session['current_server_id'] = target_server
            return redirect(url_for('server_home', server_id=target_server))
    if next_action == 'claim':
        return redirect(url_for('free_claim'))
    return redirect(url_for('user_account'))


@app.route('/account')
def user_account():
    if session.get('role') != 'user' or not session.get('user'):
        return redirect(url_for('login', next='account'))
    users = load_users()
    account = users.get(session['user'], {})
    if account.get('disabled'):
        session.clear()
        return redirect(url_for('landing'))
    return render_template('account.html', username=session['user'], account=account,
                           email=account.get('email', ''), servers=account.get('servers', []),
                           free_claimed=bool(account.get('free_claimed_at')), csrf_token=get_csrf_token())


@app.route('/free-claim', methods=['GET', 'POST'])
def free_claim():
    if session.get('role') != 'user' or not session.get('user'):
        return redirect(url_for('login', next='claim'))
    users = load_users()
    username = session['user']
    account = users.get(username)
    if not account or account.get('role') != 'user' or account.get('disabled'):
        session.clear()
        return redirect(url_for('landing'))
    if account.get('free_claimed_at'):
        return redirect(url_for('user_account'))
    if request.method == 'GET':
        return render_template('account.html', username=username, account=account,
                               email=account.get('email', ''), servers=account.get('servers', []),
                               free_claimed=False, show_claim=True, csrf_token=get_csrf_token())
    supplied_csrf = request.form.get('csrf_token', '')
    expected_csrf = session.get('pgx_csrf_token', '')
    if not expected_csrf or not secrets.compare_digest(str(expected_csrf), str(supplied_csrf)):
        return jsonify({'error': 'Security token expired. Refresh the page and try again.'}), 400
    with FREE_CLAIM_LOCK:
        users = load_users()
        account = users.get(username)
        if not account or account.get('disabled'):
            session.clear()
            return redirect(url_for('landing'))
        if account.get('free_claimed_at'):
            return redirect(url_for('user_account'))
        server = create_user_project(username, account, days=3)
        account['free_claimed_at'] = datetime.now().isoformat(timespec='seconds')
        account['free_claim_server_id'] = server['server_id']
        save_users(users)
    audit_admin_action('free_claim', f'{username}/{server["server_id"]}')
    session['current_server_id'] = server['server_id']
    return redirect(url_for('server_home', server_id=server['server_id']))


@app.route('/account/open/<server_id>')
def account_open_project(server_id):
    if session.get('role') != 'user' or not session.get('user'):
        return redirect(url_for('login', next='account'))
    server, owner = get_server_by_id(server_id)
    if not server or owner != session.get('user'):
        return jsonify({'error': 'Project not found or access denied.'}), 404
    session['current_server_id'] = server_id
    return redirect(url_for('server_home', server_id=server_id))


# ============================================
# অ্যাডমিন
# ============================================

@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    users = load_users()
    user_list = []
    total_servers = 0
    total_running = 0
    for uname, data in users.items():
        if data.get('role') == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): servers = []
        running = sum(1 for s in servers if isinstance(s, dict) and s.get('status') == 'running')
        total_servers += len(servers)
        total_running += running
        user_list.append({
            'username': uname,
            'servers': servers, 'server_count': len(servers), 'running_count': running
        })
    return render_template('admin.html', users=user_list, total_servers=total_servers, total_running=total_running)

@app.route('/admin/create_server', methods=['POST'])
def create_server():
    admin_name = session.get('user')
    users = load_users()
    admin_record = users.get(admin_name, {}) if admin_name else {}
    if not admin_name or session.get('role') != 'admin' or admin_record.get('role') != 'admin' or admin_record.get('disabled'):
        return jsonify({'success': False, 'error': 'Admin session expired. Log in again.'}), 403

    data = request.get_json(silent=True) or {}
    username = normalize_username(data.get('username'))
    password = str(data.get('password') or '')
    server_type = str(data.get('server_type') or 'python').lower()
    ram = str(data.get('ram') or '512MB')
    disk = str(data.get('disk') or '1GB')
    try:
        expiry_days = int(data.get('expiry_days', 30))
        cpu_limit = int(data.get('cpu_limit', 80))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Expiry and CPU values must be numbers.'}), 400
    if not re.fullmatch(r'[A-Za-z0-9_]{3,24}', username) or len(password) < 8:
        return jsonify({'success': False, 'error': 'Use a 3–24 character username and a password of at least 8 characters.'}), 400
    if expiry_days < 1 or expiry_days > 3650 or cpu_limit < 10 or cpu_limit > 100:
        return jsonify({'success': False, 'error': 'Expiry must be 1–3650 days and CPU 10–100%.'}), 400
    if server_type not in ('python', 'nodejs', 'node', 'javascript'):
        return jsonify({'success': False, 'error': 'Unsupported server template.'}), 400

    existing = users.get(username)
    if existing:
        if existing.get('role') != 'user' or existing.get('disabled'):
            return jsonify({'success': False, 'error': 'That username cannot receive a project.'}), 409
        # Do not silently change an existing user's login password from this form.
        if not verify_account_password(existing, password):
            return jsonify({'success': False, 'error': 'Username already exists. Enter that account’s current password or choose a new username.'}), 409
        account = existing
    else:
        account = {'password_hash': generate_password_hash(password), 'role': 'user', 'servers': [], 'created_at': datetime.now().isoformat(timespec='seconds')}
        users[username] = account

    if 'servers' not in account:
        account['servers'] = []
    if not isinstance(account.get('servers'), list):
        return jsonify({'success': False, 'error': 'This user record has an invalid projects list. Database was not changed.'}), 409

    server_id = str(uuid.uuid4())[:8]
    expiry_date = datetime.now() + timedelta(days=expiry_days)
    server_dir = get_server_dir(server_id)
    try:
        create_default_files(server_dir)
        new_server = {
            'server_id': server_id, 'link': server_id,
            'login_url': f'/{server_id}/login', 'dashboard_url': f'/{server_id}/home',
            'full_link': request.host_url.rstrip('/') + f'/{server_id}/home',
            'type': server_type, 'ram': ram, 'disk': disk,
            'status': 'stopped', 'pid': None, 'created': str(datetime.now()),
            'expiry': str(expiry_date), 'main_file': 'main.py', 'requirements_file': 'requirements.txt',
            'cpu_limit': cpu_limit, 'rate_limit_exceeded': False, 'stopped_by_user': False
        }
        account['servers'].append(new_server)
        save_users(users)
    except Exception:
        # Remove only this newly-created, unreferenced directory; never touch other bot data.
        shutil.rmtree(server_dir, ignore_errors=True)
        app.logger.exception('Could not create project for %s', username)
        return jsonify({'success': False, 'error': 'Project could not be saved. Existing account data was preserved.'}), 500

    audit_admin_action('create_project', f'{username}/{server_id}')
    return jsonify({'success': True, 'username': username, 'password': password,
                    'login_url': new_server['login_url'], 'hostname': new_server['full_link'],
                    'server_id': server_id, 'cpu_limit': cpu_limit})

@app.route('/admin/set_rate_limit/<server_id>', methods=['POST'])
def set_rate_limit(server_id):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    cpu_limit = int(request.get_json().get('cpu_limit', 80))
    users = load_users()
    for uname, udata in users.items():
        if udata.get('role') == 'admin': continue
        servers = udata.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['cpu_limit'] = cpu_limit
                save_users(users)
                return jsonify({'success': True, 'cpu_limit': cpu_limit})
    return jsonify({'error': 'Not found'}), 404

@app.route('/admin/delete_server/<username>/<server_id>', methods=['POST'])
def delete_server(username, server_id):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    users = load_users()
    if username in users:
        servers = users[username].get('servers', [])
        if not isinstance(servers, list): servers = []
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                if s.get('pid'): stop_bot_process(s['pid'])
                try: shutil.rmtree(get_server_dir(server_id))
                except: pass
                break
        users[username]['servers'] = [s for s in servers if isinstance(s, dict) and s.get('server_id') != server_id]
        if len(users[username]['servers']) == 0:
            del users[username]
        save_users(users)
    audit_admin_action('delete_project', f'{username}/{server_id}')
    return jsonify({'success': True})


# ============================================
# PGX CLOUD - ADMIN CONTROL CENTER
# ============================================

def audit_admin_action(action, details=''):
    try:
        record = {'time': datetime.now().isoformat(timespec='seconds'), 'admin': session.get('user', 'system'), 'action': action, 'details': str(details)[:500]}
        with open(os.path.join(BASE_DIR, 'admin_audit.log'), 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + '\n')
    except Exception:
        pass

def require_admin():
    return session.get('role') == 'admin' and session.get('user') in load_users()

@app.route('/admin/create_admin', methods=['POST'])
def admin_create_admin():
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    payload = request.get_json(silent=True) or {}
    username = str(payload.get('username', '')).strip()
    password = str(payload.get('password', ''))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,32}', username):
        return jsonify({'error': 'Username must be 3-32 characters (letters, numbers, . _ -).'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400
    users = load_users()
    if username in users:
        return jsonify({'error': 'Username already exists.'}), 409
    users[username] = {'password_hash': generate_password_hash(password), 'role': 'admin', 'created_at': str(datetime.now()), 'created_by': session['user']}
    save_users(users)
    audit_admin_action('create_admin', username)
    return jsonify({'success': True, 'username': username})

@app.route('/admin/set_resources/<server_id>', methods=['POST'])
def admin_set_resources(server_id):
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    payload = request.get_json(silent=True) or {}
    ram = str(payload.get('ram', '512MB')).strip().upper()
    disk = str(payload.get('disk', '1GB')).strip().upper()
    cpu = payload.get('cpu_limit', 80)
    try:
        cpu = int(cpu)
    except (TypeError, ValueError):
        return jsonify({'error': 'CPU limit must be a number.'}), 400
    if not re.fullmatch(r'\d+(MB|GB)', ram) or not re.fullmatch(r'\d+(MB|GB)', disk):
        return jsonify({'error': 'RAM and disk must use MB or GB (example: 512MB, 2GB).'}), 400
    if not 1 <= cpu <= 100:
        return jsonify({'error': 'CPU limit must be between 1 and 100.'}), 400
    users = load_users()
    for owner, account in users.items():
        if account.get('role') == 'admin':
            continue
        for server in account.get('servers', []) if isinstance(account.get('servers', []), list) else []:
            if isinstance(server, dict) and server.get('server_id') == server_id:
                server.update({'ram': ram, 'disk': disk, 'cpu_limit': cpu})
                save_users(users)
                audit_admin_action('set_resources', f'{server_id}: RAM={ram}, disk={disk}, CPU={cpu}%')
                return jsonify({'success': True, 'ram': ram, 'disk': disk, 'cpu_limit': cpu})
    return jsonify({'error': 'Project not found.'}), 404

@app.route('/admin/toggle_user/<username>', methods=['POST'])
def admin_toggle_user(username):
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    users = load_users()
    account = users.get(username)
    if not account or account.get('role') == 'admin':
        return jsonify({'error': 'User not found or cannot modify an admin.'}), 404
    account['disabled'] = not bool(account.get('disabled'))
    save_users(users)
    audit_admin_action('toggle_user', f"{username}: disabled={account.get('disabled')}")
    return jsonify({'success': True, 'disabled': account['disabled']})

@app.route('/admin/delete_user/<username>', methods=['POST'])
def admin_delete_user(username):
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    users = load_users()
    account = users.get(username)
    if not account or account.get('role') == 'admin':
        return jsonify({'error': 'User not found or cannot delete an admin.'}), 404
    for server in account.get('servers', []) if isinstance(account.get('servers', []), list) else []:
        if isinstance(server, dict):
            if server.get('pid'):
                stop_bot_process(server['pid'])
            try:
                shutil.rmtree(get_server_dir(server.get('server_id', '')))
            except Exception:
                pass
    del users[username]
    save_users(users)
    audit_admin_action('delete_user', username)
    return jsonify({'success': True})


@app.route('/admin/inspect/<server_id>')
def admin_inspect_project(server_id):
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    server, owner = get_server_by_id(server_id)
    if not server:
        return jsonify({'error': 'Project not found.'}), 404
    base = os.path.abspath(get_server_dir(server_id))
    files = []
    databases = []
    for current, dirs, names in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__', 'venv', '.venv')]
        for name in names:
            full = os.path.abspath(os.path.join(current, name))
            if not full.startswith(base + os.sep):
                continue
            rel = os.path.relpath(full, base)
            try:
                st = os.stat(full)
                files.append({'path': rel, 'size': st.st_size, 'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')})
            except OSError:
                pass
            if name.lower().endswith(('.db', '.sqlite', '.sqlite3')):
                try:
                    uri = 'file:' + full.replace('?', '%3f') + '?mode=ro'
                    con = sqlite3.connect(uri, uri=True, timeout=2)
                    tables = []
                    for row in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                        table = row[0]
                        count = con.execute('SELECT COUNT(*) FROM "' + table.replace('"','""') + '"').fetchone()[0]
                        tables.append({'name': table, 'rows': count})
                    con.close()
                    databases.append({'path': rel, 'tables': tables})
                except Exception as exc:
                    databases.append({'path': rel, 'error': str(exc)[:160]})
    log_path = os.path.join(base, 'output.log')
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as fh:
            log_lines = fh.readlines()[-250:]
        logs = ''.join(log_lines)
    except Exception:
        logs = ''
    return jsonify({'owner': owner, 'server': server, 'files': files, 'databases': databases, 'logs': logs})

@app.route('/admin/audit_data')
def admin_audit_data():
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        with open(os.path.join(BASE_DIR, 'admin_audit.log'), 'r', encoding='utf-8') as fh:
            records = [json.loads(line) for line in fh.readlines()[-100:] if line.strip()]
    except Exception:
        records = []
    return jsonify({'records': records[::-1]})

@app.route('/admin/google_accounts')
def admin_google_accounts():
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    records = list(load_google_accounts().values())
    records.sort(key=lambda item: item.get('last_login', ''), reverse=True)
    return jsonify({'accounts': records, 'total': len(records)})


@app.route('/admin/system_data')
def admin_system_data():
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    users = load_users()
    user_accounts = [u for u in users.values() if u.get('role') != 'admin']
    servers = [srv for u in user_accounts for srv in (u.get('servers', []) if isinstance(u.get('servers', []), list) else []) if isinstance(srv, dict)]
    try:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(os.getcwd())
        cpu = psutil.cpu_percent(interval=0.1)
        system = {'cpu_percent': cpu, 'ram_total_mb': round(vm.total/1048576), 'ram_used_mb': round(vm.used/1048576), 'ram_percent': vm.percent, 'disk_total_gb': round(disk.total/1073741824, 2), 'disk_used_gb': round(disk.used/1073741824, 2), 'disk_percent': disk.percent}
    except Exception:
        system = {}
    return jsonify({
        'system': system,
        'users': len(user_accounts),
        'users_data': [{'username': name, 'disabled': bool(data.get('disabled')), 'project_count': len(data.get('servers', [])) if isinstance(data.get('servers', []), list) else 0} for name, data in users.items() if data.get('role') != 'admin'],
        'admins': [{'username': name, 'owner': bool(data.get('is_owner')), 'created_by': data.get('created_by', 'system')} for name, data in users.items() if data.get('role') == 'admin'],
        'projects': len(servers),
        'running': sum(1 for srv in servers if srv.get('status') == 'running'),
        'projects_data': [{'owner': name, **srv} for name, data in users.items() if data.get('role') != 'admin' for srv in (data.get('servers', []) if isinstance(data.get('servers', []), list) else []) if isinstance(srv, dict)]
    })


# ============================================
# বট API
# ============================================

@app.route('/api/run/<server_id>', methods=['POST'])
def api_run(server_id):
    server, _ = get_server_by_id(server_id)
    if not server: return jsonify({'status': 'error', 'msg': 'Not found'})
    if server.get('status') == 'running': return jsonify({'status': 'error', 'msg': 'Already running!'})
    
    server['rate_limit_exceeded'] = False
    server['stopped_by_user'] = False
    
    pid, error = run_bot(server_id, server.get('main_file', 'main.py'), server.get('requirements_file', 'requirements.txt'))
    
    if pid:
        users = load_users()
        for uname, data in users.items():
            if data.get('role') == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    s['status'] = 'running'
                    s['pid'] = pid
                    s['started_at'] = str(datetime.now())
                    save_users(users)
                    break
        threading.Thread(target=monitor_bot, args=(server_id, pid), daemon=True).start()
        return jsonify({'status': 'success', 'msg': 'Started!'})
    return jsonify({'status': 'error', 'msg': error or 'Failed'})

@app.route('/api/stop/<server_id>', methods=['POST'])
def api_stop(server_id):
    server, _ = get_server_by_id(server_id)
    if not server: return jsonify({'status': 'error', 'msg': 'Not found'})
    
    if server.get('pid'): stop_bot_process(server['pid'])
    
    users = load_users()
    for uname, data in users.items():
        if data.get('role') == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['status'] = 'stopped'
                s['pid'] = None
                s['stopped_by_user'] = True
                save_users(users)
                break
    
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n[{datetime.now().strftime('%I:%M:%S %p')}] Server stopped by user\n")
    except: pass
    
    return jsonify({'status': 'success', 'msg': 'Stopped'})

@app.route('/api/logs/<server_id>')
def api_logs(server_id):
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8') as f: logs = f.read()
    else: logs = ""
    return jsonify({'logs': logs})

@app.route('/api/clear_logs/<server_id>', methods=['POST'])
def api_clear_logs(server_id):
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        if os.path.exists(log_file):
            try: os.remove(log_file)
            except: open(log_file, 'w').close()
        return jsonify({'status': 'success', 'msg': 'Cleared'})
    except: return jsonify({'status': 'error'}), 500

@app.route('/api/command', methods=['POST'])
def api_command():
    data = request.get_json()
    cmd = data.get('cmd', '')
    server_id = data.get('server_id', '')
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=get_server_dir(server_id), timeout=30,
                              creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        output = (result.stdout + result.stderr)[:2000]
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] $ {cmd}\n{output}\n")
        return jsonify({'status': 'success', 'output': output})
    except: return jsonify({'status': 'error', 'msg': 'Timeout'})

@app.route('/api/stats/<server_id>')
def api_stats(server_id):
    server, _ = get_server_by_id(server_id)
    if not server:
        return jsonify({'cpu': '0%', 'ram': '0 MB', 'uptime': '0h', 'status': 'unknown', 'cpu_limit': 80, 'net_in': '0 KB', 'net_out': '0 KB'})
    
    uptime, cpu, ram, net_in, net_out = "0h 0m", "0%", "0 MB", "0 KB", "0 KB"
    
    if server.get('status') == 'running' and server.get('pid'):
        stats = get_process_stats(server['pid'])
        cpu = f"{stats['cpu_percent']}%"
        ram = stats['ram_display']
        net_in, net_out = get_network_stats(server['pid'])
    
    if server.get('status') == 'running' and server.get('started_at'):
        try:
            start = datetime.strptime(server['started_at'], '%Y-%m-%d %H:%M:%S.%f')
            diff = datetime.now() - start
            if diff.days > 0: uptime = f"{diff.days}d {diff.seconds//3600}h"
            else:
                h, m, s = diff.seconds // 3600, (diff.seconds % 3600) // 60, diff.seconds % 60
                uptime = f"{h}h {m}m {s}s"
        except: pass
    
    return jsonify({'cpu': cpu, 'ram': ram, 'uptime': uptime, 'net_in': net_in, 'net_out': net_out, 'cpu_limit': server.get('cpu_limit', 80), 'status': server.get('status', 'stopped')})

# ============================================
# পাসওয়ার্ড চেঞ্জ
# ============================================

@app.route('/api/change_password/<server_id>', methods=['POST'])
def api_change_password(server_id):
    if 'user' not in session: return jsonify({'error': 'Please login first!'}), 403
    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password: return jsonify({'error': 'All fields are required!'})
    if len(new_password) < 4: return jsonify({'error': 'Password must be at least 4 characters!'})
    
    users = load_users()
    username = session.get('user')
    
    if username in users:
        if users[username].get('password') == current_password:
            users[username]['password'] = new_password
            save_users(users)
            return jsonify({'success': True, 'msg': 'Password changed!'})
        return jsonify({'error': 'Current password is incorrect!'})
    return jsonify({'error': 'User not found!'}), 404

# ============================================
# 🔥 GITHUB API (Git ছাড়া Python Download)
# ============================================

@app.route('/api/github/deploy/<server_id>', methods=['POST'])
def api_github_deploy(server_id):
    """Download GitHub repo without git - using Python requests"""
    data = request.get_json()
    repo_url = data.get('repo_url', '').strip()
    access_token = data.get('access_token', '').strip()
    is_private = data.get('is_private', False)
    
    if not repo_url:
        return jsonify({'status': 'error', 'msg': 'Repository URL is required!'}), 400
    
    server_dir = get_server_dir(server_id)
    log_file = os.path.join(server_dir, 'github_deploy.log')
    
    # Clear old deploy log
    try:
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] Starting GitHub deployment...\n")
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] Repository: {repo_url}\n")
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] Type: {'Private' if is_private else 'Public'}\n")
            f.write("─" * 40 + "\n")
    except:
        pass
    
    def deploy_thread():
        try:
            import requests
            import shutil
            
            def deploy_log(msg):
                try:
                    with open(log_file, 'a', encoding='utf-8') as f:
                        f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] {msg}\n")
                        f.flush()
                except:
                    pass
            
            deploy_log("Preparing deployment...")
            
            # Parse GitHub URL → owner/repo/branch
            # Support: https://github.com/user/repo or https://github.com/user/repo.git
            # Also: https://github.com/user/repo/tree/branch
            
            parsed = urlparse(repo_url.strip())
            if parsed.scheme != 'https' or parsed.hostname != 'github.com':
                deploy_log("❌ Error: Use a valid https://github.com/owner/repository URL.")
                return
            parts = [unquote(part) for part in parsed.path.strip('/').split('/') if part]
            if len(parts) < 2:
                deploy_log("❌ Error: Invalid GitHub repository URL format!")
                return
            owner = parts[0]
            repo = parts[1].removesuffix('.git')
            branch = 'main'
            if len(parts) >= 4 and parts[2] == 'tree':
                branch = '/'.join(parts[3:])
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', owner) or not re.fullmatch(r'[A-Za-z0-9_.-]+', repo) or not branch:
                deploy_log("❌ Error: Invalid repository owner, name or branch.")
                return
            
            deploy_log(f"Owner: {owner}")
            deploy_log(f"Repository: {repo}")
            deploy_log(f"Branch: {branch}")
            deploy_log(f"Downloading ZIP archive...")
            
            # Build API URL
            api_url = f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/zipball/{quote(branch, safe='/')}"
            
            headers = {'Accept': 'application/vnd.github.v3+json'}
            if is_private and access_token:
                headers['Authorization'] = f'token {access_token}'
                deploy_log("Using access token for authentication")
            
            # Download ZIP
            response = requests.get(api_url, headers=headers, stream=True, timeout=60)
            
            if response.status_code == 200:
                deploy_log("✓ Repository downloaded successfully!")
                deploy_log("Extracting files...")
                
                # Save to temp zip
                temp_zip = os.path.join(server_dir, '_github_temp.zip')
                with open(temp_zip, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                # Extract
                try:
                    with zipfile.ZipFile(temp_zip, 'r') as zf:
                        # GitHub zipball has a root folder like: owner-repo-commit_hash
                        # Extract everything inside that folder
                        names = zf.namelist()
                        root_folder = names[0].replace('\\', '/').split('/')[0] if names else ''
                        if not root_folder:
                            raise ValueError('The GitHub archive is empty.')
                        for member_info in zf.infolist():
                            member = member_info.filename.replace('\\', '/')
                            path_parts = [part for part in member.split('/') if part]
                            if not path_parts or path_parts[0] != root_folder:
                                raise ValueError('Unexpected path in GitHub archive.')
                            if any(part in ('.', '..') for part in path_parts):
                                raise ValueError('Unsafe path found in GitHub archive.')
                            # Reject symbolic links rather than allowing archive-controlled links.
                            unix_mode = (member_info.external_attr >> 16) & 0o170000
                            if unix_mode == 0o120000:
                                raise ValueError('Symbolic links are not allowed in GitHub archives.')
                            relative_path = '/'.join(path_parts[1:])
                            if not relative_path:
                                continue
                            target_path = safe_project_path(server_id, relative_path)
                            if member_info.is_dir():
                                os.makedirs(target_path, exist_ok=True)
                            else:
                                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                with zf.open(member_info) as source, open(target_path, 'wb') as target:
                                    shutil.copyfileobj(source, target)
                                deploy_log(f"  ✓ {relative_path}")
                    
                    deploy_log("")
                    deploy_log("✅ Deployment completed successfully!")
                    deploy_log(f"Files extracted to: {server_dir}")
                    
                except Exception as e:
                    deploy_log(f"❌ Extraction error: {str(e)}")
                finally:
                    # Clean up temp zip
                    try:
                        os.remove(temp_zip)
                    except:
                        pass
                    
            elif response.status_code == 404:
                deploy_log("❌ Error: Repository not found!")
                deploy_log("Check if the URL is correct and the repo is accessible")
            elif response.status_code == 401:
                deploy_log("❌ Error: Authentication failed!")
                deploy_log("Check your access token (for private repos)")
            elif response.status_code == 403:
                deploy_log("❌ Error: Rate limit exceeded or access denied!")
                deploy_log("Try again later or use an access token")
            else:
                deploy_log(f"❌ Error: HTTP {response.status_code}")
                deploy_log(f"Response: {response.text[:200]}")
            
        except requests.exceptions.Timeout:
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] ❌ Error: Connection timeout! Check your internet.\n")
            except:
                pass
        except Exception as e:
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] ❌ Error: {str(e)}\n")
            except:
                pass
    
    threading.Thread(target=deploy_thread, daemon=True).start()
    return jsonify({'status': 'success', 'msg': 'Deployment started! Check terminal for progress.'})

@app.route('/api/github/logs/<server_id>')
def api_github_logs(server_id):
    """Get GitHub deployment logs"""
    log_file = os.path.join(get_server_dir(server_id), 'github_deploy.log')
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = f.read()
        except:
            logs = "> Ready for deployment..."
    else:
        logs = "> Ready for deployment..."
    return jsonify({'logs': logs})

@app.route('/api/github/clear_logs/<server_id>', methods=['POST'])
def api_github_clear_logs(server_id):
    """Clear GitHub deployment logs"""
    log_file = os.path.join(get_server_dir(server_id), 'github_deploy.log')
    try:
        if os.path.exists(log_file):
            os.remove(log_file)
        return jsonify({'status': 'success'})
    except:
        return jsonify({'status': 'error'}), 500

# ============================================
# ফাইল API
# ============================================

@app.route('/api/files/<server_id>')
def api_files(server_id):
    folder = request.args.get('folder', '')
    server_dir = get_server_dir(server_id)
    if folder:
        try:
            server_dir = safe_project_path(server_id, folder)
        except ValueError:
            return jsonify({'error': 'Invalid folder path'}), 400
    if not os.path.exists(server_dir): return jsonify({'files': []})
    
    files = []
    try:
        for item in os.listdir(server_dir):
            item_path = os.path.join(server_dir, item)
            files.append({'name': item, 'is_dir': os.path.isdir(item_path), 'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0, 'modified': datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M')})
    except: pass
    return jsonify({'files': files})

@app.route('/api/file/<server_id>', methods=['GET'])
def api_get_file(server_id):
    filename = request.args.get('filename', '')
    try:
        filepath = safe_project_path(server_id, filename)
    except ValueError:
        return jsonify({'error': 'Invalid file path'}), 400
    if os.path.exists(filepath) and os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8') as f: return jsonify({'content': f.read()})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/file/<server_id>', methods=['POST'])
def api_save_file(server_id):
    data = request.get_json()
    try:
        filepath = safe_project_path(server_id, data.get('filename', ''))
    except ValueError:
        return jsonify({'error': 'Invalid file path'}), 400
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f: f.write(data.get('content', ''))
    return jsonify({'success': True})

@app.route('/api/file/<server_id>', methods=['DELETE'])
def api_delete_file(server_id):
    data = request.get_json()
    try:
        filepath = safe_project_path(server_id, data.get('filename', ''))
    except ValueError:
        return jsonify({'error': 'Invalid file path'}), 400
    if os.path.exists(filepath):
        if os.path.isdir(filepath): shutil.rmtree(filepath)
        else: os.remove(filepath)
    return jsonify({'success': True})

@app.route('/api/upload/<server_id>', methods=['POST'])
def api_upload(server_id):
    if 'file' not in request.files: return jsonify({'error': 'No file'}), 400
    folder = request.form.get('folder', '')
    server_dir = get_server_dir(server_id)
    if folder:
        try:
            server_dir = safe_project_path(server_id, folder)
        except ValueError:
            return jsonify({'error': 'Invalid folder path'}), 400
        os.makedirs(server_dir, exist_ok=True)
    file = request.files['file']
    safe_name = os.path.basename(file.filename or '')
    if not safe_name:
        return jsonify({'error': 'Invalid filename'}), 400
    file.save(os.path.join(server_dir, safe_name))
    return jsonify({'success': True})

@app.route('/api/create_folder/<server_id>', methods=['POST'])
def api_create_folder(server_id):
    data = request.get_json()
    os.makedirs(safe_project_path(server_id, data.get('foldername', '')), exist_ok=True)
    return jsonify({'success': True})

@app.route('/api/rename/<server_id>', methods=['POST'])
def api_rename(server_id):
    d = request.get_json()
    server_dir = get_server_dir(server_id)
    try:
        old_path = safe_project_path(server_id, d.get('old_name', ''))
        new_path = safe_project_path(server_id, d.get('new_name', ''))
    except ValueError:
        return jsonify({'error': 'Invalid file path'}), 400
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
        return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/unzip/<server_id>', methods=['POST'])
def api_unzip(server_id):
    data = request.get_json()
    try:
        zip_path = safe_project_path(server_id, data.get('filename', ''))
    except ValueError:
        return jsonify({'status': 'error', 'msg': 'Invalid zip path'}), 400
    if os.path.exists(zip_path) and zip_path.endswith('.zip'):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                dest = os.path.dirname(zip_path)
                for member in zf.infolist():
                    target = os.path.realpath(os.path.join(dest, member.filename))
                    if os.path.commonpath([dest, target]) != dest:
                        raise ValueError('Unsafe archive path')
                    if member.is_dir():
                        os.makedirs(target, exist_ok=True)
                    else:
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        with zf.open(member) as src, open(target, 'wb') as out:
                            shutil.copyfileobj(src, out)
            return jsonify({'status': 'success', 'msg': 'Extracted!'})
        except Exception as e: return jsonify({'status': 'error', 'msg': str(e)})
    return jsonify({'status': 'error', 'msg': 'Invalid zip'}), 400

@app.route('/api/get_startup/<server_id>')
def api_get_startup(server_id):
    server, _ = get_server_by_id(server_id)
    if server: return jsonify({'main_file': server.get('main_file', 'main.py'), 'requirements_file': server.get('requirements_file', 'requirements.txt')})
    return jsonify({'main_file': 'main.py', 'requirements_file': 'requirements.txt'})

@app.route('/api/set_startup/<server_id>', methods=['POST'])
def api_set_startup(server_id):
    d = request.get_json(silent=True) or {}
    try:
        safe_project_path(server_id, d.get('main_file', 'main.py'))
        req_value = d.get('requirements_file')
        if req_value:
            safe_project_path(server_id, req_value)
    except ValueError:
        return jsonify({'error': 'Invalid startup file path'}), 400
    users = load_users()
    for uname, udata in users.items():
        if udata.get('role') == 'admin': continue
        servers = udata.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['main_file'] = d.get('main_file', 'main.py')
                s['requirements_file'] = d.get('requirements_file')
                save_users(users)
                return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404

# ============================================
# স্টার্ট
# ============================================

if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("🚀 PGX CLOUD - HOSTING PANEL")
    print("=" * 50)
    print('PGX CLOUD starting; use the domain configured by your hosting provider.')
    print('Admin sign-in is available at /login; credentials are documented in PGX_README.txt.')
    print("=" * 50 + "\n")
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', '5000')))
