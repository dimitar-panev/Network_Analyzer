import ipaddress
import json
import platform
import socket
import ssl
import subprocess
from datetime import datetime

import psutil
import requests
import dns.resolver
from flask import Blueprint, render_template, request, Response, stream_with_context

try:
    import whois
except Exception:
    whois = None

# Add speedtest import (optional at runtime)
try:
    import speedtest
except Exception:
    speedtest = None

bp = Blueprint('routes', __name__)


# Helpers

def run_command(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def is_valid_hostname(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


@bp.route('/')
def index():
    tools = [
        {"name": "Ping", "path": "ping"},
        {"name": "Traceroute", "path": "traceroute"},
        {"name": "DNS Lookup", "path": "dns"},
        {"name": "WHOIS", "path": "whois"},
        {"name": "Port Scanner", "path": "port-scan"},
        {"name": "HTTP Tester", "path": "http"},
        {"name": "SSL/TLS Info", "path": "ssl"},
        {"name": "Subnet Calculator", "path": "subnet"},
        {"name": "Interfaces", "path": "interfaces"},
        {"name": "ARP Table", "path": "arp"},
        {"name": "Speedtest", "path": "speedtest"},
    ]
    return render_template('index.html', tools=tools)


@bp.route('/ping', methods=['GET', 'POST'])
def ping():
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '').strip()
        count = request.form.get('count', '4')
        if host:
            cmd = ['ping', '-c', count, host]
            code, out, err = run_command(cmd, timeout=15)
            result = out if out else err
    return render_template('ping.html', result=result)


@bp.route('/traceroute', methods=['GET', 'POST'])
def traceroute():
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '').strip()
        if host:
            tracer_cmd = 'traceroute' if platform.system() != 'Windows' else 'tracert'
            cmd = [tracer_cmd, host]
            code, out, err = run_command(cmd, timeout=40)
            result = out if out else err
    return render_template('traceroute.html', result=result)


@bp.route('/dns', methods=['GET', 'POST'])
def dns_lookup():
    answer = None
    error = None
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        record = request.form.get('record', 'A')
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5.0
            ans = resolver.resolve(name, record)
            answer = [str(r) for r in ans]
        except Exception as e:
            error = str(e)
    return render_template('dns.html', answer=answer, error=error)


@bp.route('/whois', methods=['GET', 'POST'])
def whois_lookup():
    info = None
    error = None
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        try:
            if whois is None:
                raise RuntimeError('python-whois not installed')
            w = whois.whois(query)
            # Convert to JSON-serializable
            def default(o):
                if isinstance(o, (datetime, )):
                    return o.isoformat()
                if isinstance(o, set):
                    return list(o)
                return str(o)
            info = json.dumps(w, default=default, indent=2)
        except Exception as e:
            error = str(e)
    return render_template('whois.html', info=info, error=error)


@bp.route('/port-scan', methods=['GET', 'POST'])
def port_scan():
    results = None
    error = None
    if request.method == 'POST':
        host = request.form.get('host', '').strip()
        ports = request.form.get('ports', '').strip()
        timeout = float(request.form.get('timeout', '0.5') or '0.5')
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            targets: list[int] = []
            for part in ports.split(','):
                part = part.strip()
                if not part:
                    continue
                if '-' in part:
                    a, b = part.split('-', 1)
                    targets.extend(range(int(a), int(b) + 1))
                else:
                    targets.append(int(part))

            targets = sorted(set(t for t in targets if 1 <= t <= 65535))
            results = []

            def check_port(p: int) -> tuple[int, str]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                try:
                    s.connect((host, p))
                    return (p, 'open')
                except Exception:
                    return (p, 'closed')
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            max_workers = min(max(10, len(targets)), 100)
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                future_map = {ex.submit(check_port, p): p for p in targets}
                for fut in as_completed(future_map):
                    results.append(fut.result())

            # Present sorted by port
            results.sort(key=lambda x: x[0])
        except Exception as e:
            error = str(e)
    return render_template('port_scan.html', results=results, error=error)

@bp.route('/http', methods=['GET', 'POST'])
def http_tester():
    resp = None
    error = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        method = request.form.get('method', 'GET')
        headers_text = request.form.get('headers', '').strip()
        body = request.form.get('body', '')
        try:
            headers = {}
            if headers_text:
                for line in headers_text.splitlines():
                    if ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.strip()] = v.strip()
            r = requests.request(method.upper(), url, headers=headers, data=body, timeout=10)
            resp = {
                'status_code': r.status_code,
                'headers': dict(r.headers),
                'text': r.text[:10000],
            }
        except Exception as e:
            error = str(e)
    return render_template('http.html', resp=resp, error=error)


@bp.route('/ssl', methods=['GET', 'POST'])
def ssl_info():
    info = None
    error = None
    if request.method == 'POST':
        host = request.form.get('host', '').strip()
        port = int(request.form.get('port', '443') or '443')
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info = json.dumps(cert, indent=2)
        except Exception as e:
            error = str(e)
    return render_template('ssl.html', info=info, error=error)


@bp.route('/subnet', methods=['GET', 'POST'])
def subnet_calc():
    result = None
    error = None
    if request.method == 'POST':
        cidr = request.form.get('cidr', '').strip()
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            result = {
                'network': str(net.network_address),
                'broadcast': str(net.broadcast_address),
                'netmask': str(net.netmask),
                'hostmask': str(net.hostmask),
                'hosts': [str(h) for h in list(net.hosts())[:256]],
                'num_hosts': net.num_addresses - 2 if not net.is_private else net.num_addresses,
            }
        except Exception as e:
            error = str(e)
    return render_template('subnet.html', result=result, error=error)


@bp.route('/interfaces')
def interfaces():
    nics = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    data = {}
    for name, addrs in nics.items():
        data[name] = {
            'addrs': [f"{a.family.name if hasattr(a.family,'name') else a.family}: {a.address}/{a.netmask}" for a in addrs],
            'isup': stats.get(name).isup if name in stats else None,
            'speed': stats.get(name).speed if name in stats else None,
            'mtu': stats.get(name).mtu if name in stats else None,
        }
    return render_template('interfaces.html', data=data)


@bp.route('/arp')
def arp_table():
    # Try psutil first
    entries = []
    try:
        for c in psutil.net_connections(kind='inet'):
            pass
    except Exception:
        pass
    # Fallback to command
    code, out, err = run_command(['ip', 'neigh', 'show'])
    lines = out.splitlines() if out else []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[0]
            mac = parts[4] if len(parts) > 4 else 'unknown'
            state = parts[-1]
            entries.append({'ip': ip, 'mac': mac, 'state': state})
    return render_template('arp.html', entries=entries)


@bp.route('/speedtest', methods=['GET', 'POST'])
def speedtest_view():
    result = None
    error = None
    if request.method == 'POST':
        try:
            if speedtest is None:
                raise RuntimeError('speedtest-cli not installed')
            st = speedtest.Speedtest()
            st.get_best_server()
            dl = st.download()  # bits per second
            ul = st.upload()
            ping_ms = st.results.ping
            srv = st.results.server
            result = {
                'download_mbps': round(dl / 1_000_000, 2),
                'upload_mbps': round(ul / 1_000_000, 2),
                'ping_ms': round(ping_ms, 2) if ping_ms is not None else None,
                'server': {
                    'sponsor': srv.get('sponsor') if srv else None,
                    'name': srv.get('name') if srv else None,
                    'country': srv.get('country') if srv else None,
                }
            }
        except Exception as e:
            error = str(e)
    return render_template('speedtest.html', result=result, error=error)


@bp.route('/stream/ping')
def stream_ping():
    host = request.args.get('host', '').strip()
    if not host:
        return Response('data: Missing host\n\n', mimetype='text/event-stream')
    continuous = request.args.get('continuous', '0') == '1'
    count = request.args.get('count', '').strip()
    interval = request.args.get('interval', '1').strip()

    cmd = ['ping']
    if interval:
        try:
            if float(interval) > 0:
                cmd += ['-i', interval]
        except Exception:
            pass
    if not continuous and count:
        cmd += ['-c', count]
    cmd += [host]

    def generate():
        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in iter(proc.stdout.readline, ''):
                yield f'data: {line.rstrip()}\n\n'
            proc.wait()
            yield 'event: done\ndata: finished\n\n'
        except Exception as e:
            yield f'data: ERROR: {str(e)}\n\n'
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
    return Response(stream_with_context(generate()), mimetype='text/event-stream')
