#!/usr/bin/env python3
import json
import secrets
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
name = 'http'
status = json.loads((ROOT / 'run' / name / 'status.json').read_text())
addresses = status['addresses']
config = {
    'hostname': status['hostname'],
    'ipv4': next((a.split('/')[0] for a in addresses if '.' in a), ''),
    'ipv6': next((a.split('/')[0] for a in addresses if ':' in a), ''),
    'mac': status['mac'],
    'mtu': status['mtu'],
    'gateway4': status['gateway4'],
    'gateway6': status['gateway6'],
    'dns': status['dns'],
}
vm_dir = ROOT / 'images' / name
seed_dir = vm_dir / 'seed'
if seed_dir.exists():
    shutil.rmtree(seed_dir)
seed_dir.mkdir(parents=True)
password = secrets.token_urlsafe(18)
(vm_dir / 'console-password').write_text(password + '\n')
(vm_dir / 'console-password').chmod(0o600)
(seed_dir / 'meta-data').write_text(f'instance-id: crosvm-http-001\nlocal-hostname: crosvm-http\n')

http_server = r'''#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'crosvm-tsnet-ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

Server(('::', 80), Handler).serve_forever()
'''

self_check = r'''#!/usr/bin/python3
import json
import time
import urllib.request
from pathlib import Path
config = json.loads(Path('/etc/lab-addresses.json').read_text())
for _ in range(30):
    try:
        with urllib.request.urlopen(f"http://[{config['ipv6']}]/", timeout=2) as response:
            assert response.read() == b'crosvm-tsnet-ok\n'
        print('LAB_HTTP_READY', flush=True)
        break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit('LAB_HTTP_FAILED')
for _ in range(20):
    try:
        request = urllib.request.Request('https://ifconfig.io/ip', headers={'User-Agent': 'curl/8.0'})
        with urllib.request.urlopen(request, timeout=10) as response:
            egress = response.read().strip().decode()
        print('LAB_INTERNET_OK', egress, flush=True)
        break
    except Exception as error:
        last_error = error
        time.sleep(2)
else:
    raise SystemExit(f'LAB_INTERNET_FAILED: {last_error}')
'''

network = f'''version: 2
ethernets:
  eth0:
    match:
      macaddress: "{config['mac']}"
    set-name: eth0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    mtu: {config['mtu']}
    addresses:
      - {config['ipv6']}/128
    routes:
      - to: default
        via: {config['gateway6']}
        on-link: true
    nameservers:
      addresses: [{', '.join(config['dns'])}]
'''
(seed_dir / 'network-config').write_text(network)
user_data = f'''#cloud-config
hostname: crosvm-http
manage_etc_hosts: true
users:
  - name: lab
    gecos: Lab User
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: "{password}"
ssh_pwauth: true
package_update: false
apt:
  preserve_sources_list: false
  sources_list: |
    deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ noble main restricted universe multiverse
    deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ noble-updates main restricted universe multiverse
    deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports/ noble-security main restricted universe multiverse
write_files:
  - path: /etc/lab-addresses.json
    permissions: '0600'
    content: |
{chr(10).join('      ' + line for line in json.dumps(config, indent=2).splitlines())}
  - path: /usr/local/bin/lab-http.py
    permissions: '0755'
    content: |
{chr(10).join('      ' + line for line in http_server.splitlines())}
  - path: /usr/local/bin/lab-http-check.py
    permissions: '0755'
    content: |
{chr(10).join('      ' + line for line in self_check.splitlines())}
  - path: /etc/systemd/system/lab-http.service
    content: |
      [Unit]
      Description=Crosvm tsnet HTTP test server
      After=network-online.target
      [Service]
      ExecStart=/usr/local/bin/lab-http.py
      Restart=always
      [Install]
      WantedBy=multi-user.target
runcmd:
  - systemctl daemon-reload
  - systemctl enable --now lab-http
  - /usr/local/bin/lab-http-check.py
output:
  all: '| tee -a /var/log/cloud-init-output.log /dev/console'
'''
(seed_dir / 'user-data').write_text(user_data)
print(f"Prepared HTTP guest: {config['ipv6']}")
