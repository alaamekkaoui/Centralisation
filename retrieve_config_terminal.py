import re
from datetime import datetime, timedelta
import ping3

def process_tech_support_file(file_content):
    if isinstance(file_content, tuple):
        file_content = ''.join(file_content)

    info = {
        'Equipment': 'Unknown',
        'Version': 'Unknown',
        'SerialNumber': 'Unknown',
        'EvaluationLicenseExpires': 'Unknown',
        'LicenseState': 'Unknown',
        'Manufacturer': 'Unknown',
        'Interfaces': []
    }

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

    # Match Evaluation License State
    info['LicenseState'] = "Active"

    # Match Evaluation License Period left
    match_license_period = re.search(r'Evaluation period left: (\d+) weeks (\d+) days', file_content, re.IGNORECASE)
    if match_license_period:
        weeks_left = int(match_license_period.group(1))
        days_left = int(match_license_period.group(2))
        total_period = f"{weeks_left} weeks {days_left} days"
        print(f"Evaluation total period: {total_period}")
        info['EvaluationLicenseExpires'] = total_period

    # Determine manufacturer based on file content
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

        # Ping the IP address to determine status
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
        # Perform ping with timeout of 2 seconds
        response = ping3.ping(ip_address, timeout=2)
        
        # Check if there was a reply
        if response is not None:
            print(f"{ip_address} is active")
            return "active"
        else:
            print(f"{ip_address} is inactive")
            return "inactive"
    
    except Exception as e:
        print(f"Error while pinging {ip_address}: {e}")
        return "error"

if __name__ == "__main__":
    # Read the file content
    with open("C:\\Users\\dsdem\\OneDrive\\Bureau\\Centralisation\\device_combined_output.txt", "r") as file:
        file_content = file.read()

    # Process the file
    process_tech_support_file(file_content)
