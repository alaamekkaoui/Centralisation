from datetime import datetime, timedelta
import os
import re
from netmiko import ConnectHandler
import requests
import ping3 

# GNS3 server details
GNS3_SERVER = "http://localhost:3080"

#------------------------GNS3 API Functions------------------------#
def list_projects():
    url = f"{GNS3_SERVER}/v2/projects"
    try:
        response = requests.get(url)
        response.raise_for_status()
        projects = response.json()
        return projects if projects else []
    except requests.exceptions.RequestException as e:
        print(f"Failed to get projects: {e}")
        return []

# Function to list nodes within a specific project
def list_nodes(project_id):
    url = f"{GNS3_SERVER}/v2/projects/{project_id}/nodes"
    try:
        response = requests.get(url)
        response.raise_for_status()
        nodes = response.json()
        return nodes if nodes else []
    except requests.exceptions.RequestException as e:
        print(f"Failed to get nodes: {e}")
        return []

# Function to retrieve full node details
def get_node_details(project_id, node_id):
    url = f"{GNS3_SERVER}/v2/projects/{project_id}/nodes/{node_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        node_details = response.json()
        return node_details if node_details else {}
    except requests.exceptions.RequestException as e:
        print(f"Failed to get node details: {e}")
        return {}

# Function to start a node via GNS3 API
def start_node(node_id):
    url = f"{GNS3_SERVER}/v2/nodes/{node_id}/start"
    try:
        response = requests.post(url)
        response.raise_for_status()
        print(f"Started node {node_id}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to start node {node_id}: {e}")
        return False

# Function to stop a node via GNS3 API
def stop_node(node_id):
    url = f"{GNS3_SERVER}/v2/nodes/{node_id}/stop"
    try:
        response = requests.post(url)
        response.raise_for_status()
        print(f"Stopped node {node_id}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to stop node {node_id}: {e}")
        return False
#---------------------------------real stuff here-------------------------

from netmiko import ConnectHandler

def retrieve_config(node_ip, ssh_port, username, password):
    # Define the device dictionary for Netmiko
    device = {
        'device_type': 'cisco_ios',
        'host': node_ip,
        'username': username,
        'password': password,
        'port': 22,
        'timeout': 10,  # Adjust the timeout as needed
        'verbose': True,  # Optional, for debugging
    }

    # Files to save the retrieved configurations
    combined_output_file = f"device_combined_output.txt"
    running_config_file = f"device_running_config.txt"

    try:
        print(f"Connecting to {username}@{node_ip} on port {ssh_port} via SSH...")

        # Establish SSH connection
        net_connect = ConnectHandler(**device)

        # Send commands to retrieve various configurations
        output_license = net_connect.send_command('show license detail')
        output_version = net_connect.send_command('show version')
        output_interfaces = net_connect.send_command('show ip int brief ')
        output_running_config = net_connect.send_command('show running-config')

        # Combine outputs into a single file
        with open(combined_output_file, 'w') as f:
            f.write(f"License Details:\n{output_license}\n\n")
            f.write(f"Device Version:\n{output_version}\n\n")
            f.write(f"Interfaces Information:\n{output_interfaces}\n\n")
            f.write(f"Running Configuration:\n{output_running_config}\n\n")

        print(f"Combined output saved to {combined_output_file}")

        # Save running-config to a separate file
        with open(running_config_file, 'w') as f:
            f.write(output_running_config)

        print(f"Running configuration saved to {running_config_file}")

        net_connect.disconnect()

        return True, combined_output_file, running_config_file
    except Exception as e:
        print(f"Failed to retrieve configuration via SSH: {e}")
        return False, None, None
    
def process_tech_support_file(file_content):
    info = {
        'Equipment': 'Unknown',
        'Version': 'Unknown',
        'SerialNumber': 'Unknown',
        'EvaluationLicenseExpires': 'Unknown',
        'LicenseState': 'Unknown',
        'Manufacturer': 'Unknown',
        'Interfaces': []
    }

    if isinstance(file_content, str):
        file_content = ''.join(file_content)

    # Match hostname
    match_hostname = re.search(r'hostname\s+(\S+)', file_content, re.IGNORECASE)
    if match_hostname:
        info['Equipment'] = match_hostname.group(1)

    # Match version
    match_version = re.search(r'(Cisco IOS XE Software, Version \S+)', file_content, re.IGNORECASE)
    if match_version:
        info['Version'] = match_version.group(1)

    # Match serial number
    match_serial = re.search(r'Processor board ID\s+(\S+)', file_content, re.IGNORECASE)
    if match_serial:
        info['SerialNumber'] = match_serial.group(1)

    info['LicenseState'] = "Active"

    # Match Evaluation License Period left
    match_license_period = re.search(r'Evaluation period left: (\d+) weeks (\d+) days', file_content, re.IGNORECASE)
    if match_license_period:
        weeks_left = int(match_license_period.group(1))
        days_left = int(match_license_period.group(2))
        total_period = f"{weeks_left} weeks {days_left} days"
        info['EvaluationLicenseExpires'] = total_period

    # Determine manufacturer
    if 'cisco' in file_content.lower():
        info['Manufacturer'] = 'Cisco'
    elif 'fortinet' in file_content.lower():
        info['Manufacturer'] = 'Fortinet'
    elif 'aruba' in file_content.lower():
        info['Manufacturer'] = 'Aruba'
    elif 'sophos' in file_content.lower():
        info['Manufacturer'] = 'Sophos'

    # Match and process GigabitEthernet interface information
    interface_regex = re.compile(r'interface (GigabitEthernet\d+)\n'
                                 r'.*?ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)\n'
                                 r'.*?Hardware is.*?, address is (\S+)', re.IGNORECASE | re.DOTALL)
    for match in interface_regex.finditer(file_content):
        interface_name = match.group(1)
        ip_address = match.group(2)
        subnet_mask = match.group(3)
        mac_address = match.group(4)

        status = ping(ip_address)

        interface_info = {
            'Interface': interface_name,
            'IPAddress': ip_address,
            'SubnetMask': subnet_mask,
            'MACAddress': mac_address,
            'Status': status
        }
        info['Interfaces'].append(interface_info)

    # Process output of "show ip interface brief"
    match_ip_int_brief = re.findall(r'(\S+)\s+(\d+\.\d+\.\d+\.\d+|unassigned)\s+YES\s+\S+\s+(\S+)\s+(\S+)', file_content)
    for match in match_ip_int_brief:
        interface_name, ip_address, status, protocol = match
        interface_info = {
            'Interface': interface_name,
            'IPAddress': ip_address,
            'Status': status,
            'Protocol': protocol
        }
        info['Interfaces'].append(interface_info)

    print("Processed tech support file:", info)
    return info

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt'}

def ping(ip_address):
    try:
        response = ping3.ping(ip_address, timeout=2)
        if response is not None:
            print(f"{ip_address} is active")
            return "active"
        else:
            print(f"{ip_address} is inactive")
            return "inactive"
    except Exception as e:
        print(f"Error while pinging {ip_address}: {e}")
        return "error"
