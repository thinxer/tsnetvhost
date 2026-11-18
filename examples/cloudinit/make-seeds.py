#!/usr/bin/env python3
import json
import secrets
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

TEST_SCRIPT = r'''#!/usr/bin/python3
import json
import socket
import subprocess
import threading
import time
from pathlib import Path

vm = Path('/etc/hostname').read_text().strip()
config = json.loads(Path('/etc/lab-addresses.json').read_text())
peer = config['peer']
own4 = config['ipv4']
own6 = config['ipv6']
peer4 = config['peer_ipv4']
peer6 = config['peer_ipv6']

print('LAB_GUEST_READY', vm, flush=True)
subprocess.run(['ip', '-details', 'link', 'show'], check=False)
subprocess.run(['ip', 'addr', 'show'], check=False)
subprocess.run(['ip', 'route', 'show'], check=False)
subprocess.run(['ip', '-6', 'route', 'show'], check=False)

def ping(family, address):
    for _ in range(45):
        result = subprocess.run(['ping', family, '-c', '1', '-W', '2', address])
        if result.returncode == 0:
            return True
        time.sleep(2)
    return False

if not ping('-4', peer4):
    raise SystemExit('LAB_IPV4_PING_FAILED')
print('LAB_IPV4_PING_OK', vm, flush=True)
if not ping('-6', peer6):
    raise SystemExit('LAB_IPV6_PING_FAILED')
print('LAB_IPV6_PING_OK', vm, flush=True)

tcp_errors = []
def tcp_server():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((own4, 20000))
            server.listen(1)
            server.settimeout(90)
            connection, _ = server.accept()
            with connection:
                data = connection.recv(1024)
                connection.sendall(data)
                if not data.startswith(b'lab-'):
                    raise RuntimeError('invalid TCP payload')
    except Exception as error:
        tcp_errors.append(error)

thread = threading.Thread(target=tcp_server)
thread.start()
payload = f'lab-{vm}'.encode()
for _ in range(90):
    try:
        connection = socket.create_connection((peer4, 20000), timeout=2)
        break
    except OSError:
        time.sleep(1)
else:
    raise SystemExit('LAB_TCP_CONNECT_FAILED')
with connection:
    connection.sendall(payload)
    assert connection.recv(1024) == payload
thread.join()
if tcp_errors:
    raise tcp_errors[0]
print('LAB_TCP_OK', vm, flush=True)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
    receiver.bind((own4, 20001))
    receiver.settimeout(2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for _ in range(45):
            sender.sendto(f'udp-{vm}'.encode(), (peer4, 20001))
            try:
                data, _ = receiver.recvfrom(1024)
                break
            except TimeoutError:
                pass
        else:
            raise SystemExit('LAB_UDP_RECV_FAILED')
    assert data.startswith(b'udp-')
print('LAB_UDP_OK', vm, flush=True)
print('LAB_ALL_TESTS_PASSED', vm, flush=True)
'''

def load_status(name):
    status = json.loads((ROOT / 'run' / name / 'status.json').read_text())
    addresses = status['addresses']
    return {
        'hostname': status['hostname'],
        'ipv4': next((a.split('/')[0] for a in addresses if '.' in a), ''),
        'ipv6': next((a.split('/')[0] for a in addresses if ':' in a), ''),
        'mac': status['mac'],
        'mtu': status['mtu'],
        'gateway4': status['gateway4'],
        'gateway6': status['gateway6'],
        'dns': status['dns'],
    }

for name in ('vm1', 'vm2'):
    peer_name = 'vm2' if name == 'vm1' else 'vm1'
    own = load_status(name)
    peer = load_status(peer_name)
    own['peer'] = peer_name
    own['peer_ipv4'] = peer['ipv4']
    own['peer_ipv6'] = peer['ipv6']
    password = secrets.token_urlsafe(18)
    vm_dir = ROOT / 'images' / name
    seed_dir = vm_dir / 'seed'
    if seed_dir.exists():
        shutil.rmtree(seed_dir)
    seed_dir.mkdir(parents=True)
    (vm_dir / 'console-password').write_text(password + '\n')
    (vm_dir / 'console-password').chmod(0o600)
    (seed_dir / 'meta-data').write_text(f'instance-id: {name}-001\nlocal-hostname: {name}\n')
    (seed_dir / 'lab-addresses.json').write_text(json.dumps(own, indent=2) + '\n')
    network = f'''version: 2
ethernets:
  eth0:
    match:
      macaddress: "{own['mac']}"
    set-name: eth0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    mtu: {own['mtu']}
    addresses:
      - {own['ipv4']}/32
      - {own['ipv6']}/128
    routes:
      - to: default
        via: {own['gateway4']}
        on-link: true
      - to: default
        via: {own['gateway6']}
        on-link: true
    nameservers:
      addresses: [{', '.join(own['dns'])}]
'''
    (seed_dir / 'network-config').write_text(network)
    user_data = f'''#cloud-config
hostname: {name}
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
{chr(10).join('      ' + line for line in json.dumps(own, indent=2).splitlines())}
  - path: /usr/local/bin/lab-test.py
    permissions: '0755'
    content: |
{chr(10).join('      ' + line for line in TEST_SCRIPT.splitlines())}
runcmd:
  - /usr/local/bin/lab-test.py
output:
  all: '| tee -a /var/log/cloud-init-output.log /dev/console'
'''
    (seed_dir / 'user-data').write_text(user_data)
    print(f'Prepared {name}: {own["ipv4"]} {own["ipv6"]}')
