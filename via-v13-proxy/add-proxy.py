# Import required libraries
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
import urllib3
from cryptography.hazmat.primitives import hashes
import time
# Suppress warnings for insecure connections (not for production use)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to retrieve the SHA-256 thumbprint of a TLS certificate from a remote host
def get_cert_thumbprints_from_url(hostname, port=443):
    """
    Connects to the given hostname:port, retrieves the TLS certificate, and returns the SHA-256 thumbprint as a hex string.
    """
    context = ssl._create_unverified_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    sha256_thumbprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    return sha256_thumbprint

# Veeam Backup & Replication (VBR) server and credentials
VBR_SERVER = 'https://fqdn_or_ip:9419'  # VBR server address
USERNAME = 'admin'                     # VBR username
PASSWORD = 'password'                # VBR password

# Linux server details to be added as managed server
LINUX_HOST = 'fqdn_or_ip'           # Linux server address or FQDN
LINUX_PORT = 443                            # Linux server SSH/TLS port


# Authenticate to Veeam REST API (OAuth2)
session_url = f'{VBR_SERVER}/api/oauth2/token'
data = {
    'grant_type': 'password',
    'username': USERNAME,
    'password': PASSWORD,
    'scope': 'Service'
}
headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}

response = requests.post(session_url, data=data, headers=headers, verify=False)
if response.status_code != 200:
    raise Exception(f'Authentication failed: {response.text}')

# Store the access token for subsequent API calls
token = response.json()['access_token']


# Get TLS certificate SHA-256 thumbprint of the Linux server
try:
    sha256_thumbprint = get_cert_thumbprints_from_url(LINUX_HOST, LINUX_PORT)
    print(f'{LINUX_HOST} TLS certificate SHA-256 thumbprint: {sha256_thumbprint}')
except Exception as e:
    print(f'Could not retrieve TLS certificate thumbprint: {e}')


# Add Linux server as managed server
url = f'{VBR_SERVER}/api/v1/backupInfrastructure/managedServers'
headers = {
    "x-api-version": "1.3-rev0",
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
payload = {
    "type": "LinuxHost",
    "credentialsStorageType": "Certificate",
    "name": LINUX_HOST,
    "description": "Added via script using TLS certificate (application thumbprint)",
    "sshFingerprint": sha256_thumbprint,
}

response = requests.post(url, headers=headers, json=payload, verify=False)


if response.status_code == 201:
    print(f'{LINUX_HOST} added to VBR inventory.')
else:
    print(f'Failed to add Linux server: {response.status_code} {response.text}')

# Wait to ensure the server is fully registered before querying
print(f'Waiting 30 seconds for {LINUX_HOST} to be fully registered...')
time.sleep(30)

# Get all managed servers and extract id by name
url = f'{VBR_SERVER}/api/v1/backupInfrastructure/managedServers'
headers = {
    "x-api-version": "1.3-rev0",
    'Authorization': f'Bearer {token}',
}

response = requests.get(url, headers=headers, verify=False)

if response.status_code == 200:
    print('Server list retrieved successfully.')
    # Extract id by name
    target_name = LINUX_HOST  # or set to any name you want to search for
    found_id = None
    data = response.json()
    for server in data.get('data', []):
        if server.get('name') == target_name:
            found_id = server.get('id')
            print(f"ID for '{target_name}': {found_id}")
            break
    if not found_id:
        print(f"No server found with name: {target_name}")
else:
    print(f'Failed to retrieve managed servers: {response.status_code} {response.text}')


# Add proxy server
url = f'{VBR_SERVER}/api/v1/backupInfrastructure/proxies'
headers = {
    "x-api-version": "1.3-rev0",
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}

payload = {
    "type": "ViProxy",
    "name" : LINUX_HOST,
    "description": "Added via REST API as VMware proxy",
    "server": {
        "hostId": found_id,
        "transportMode": "auto",
        "failoverToNetwork": True,
        "maxTaskCount": 2
    }
}

response = requests.post(url, headers=headers, json=payload, verify=False)

if response.status_code == 201:
    print(f'Adding proxy server {LINUX_HOST}')
    data = response.json()
    print(f'Job id: {data.get('id')}')
else:
    print(f'Failed to add proxy server: {response.status_code} {response.text}')

