import os
import re
import retrieve_config_terminal
import requests
from flask import Flask, render_template, redirect, url_for, request, jsonify

app = Flask(__name__)

# GNS3 server details
GNS3_SERVER = "http://localhost:3080"

# Function to list all projects
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

def retrieve_config(node_ip, ssh_port, username, password):
    try:
        print(f"Connecting to {node_ip} on port {ssh_port} via SSH...")
        client = retrieve_config_terminal.SSHClient()
        client.set_missing_host_key_policy(retrieve_config_terminal.AutoAddPolicy())
        client.connect(node_ip, port=ssh_port, username=username, password=password, timeout=5)
        
        # Retrieve "show tech-support"
        stdin, stdout, stderr = client.exec_command("show tech-support")
        tech_support_output = stdout.read().decode()

        # Retrieve "show running-config"
        stdin, stdout, stderr = client.exec_command("show running-config")
        running_config_output = stdout.read().decode()

        client.close()
        
        current_path = os.path.dirname(os.path.abspath(__file__))
        tech_support_filename = os.path.join(current_path, f"tech_support.txt")
        running_config_filename = os.path.join(current_path, f"running_config.txt")

        with open(tech_support_filename, "w") as f:
            f.write(tech_support_output)
        print(f"Tech support file saved: {tech_support_filename}")

        with open(running_config_filename, "w") as f:
            f.write(running_config_output)
        print(f"Running config file saved: {running_config_filename}")

        return True, tech_support_filename, running_config_filename
    except Exception as e:
        print(f"Failed to retrieve configuration via SSH: {e}")
        return False, None, None

def process_tech_support_file(file_content):
    info = {
        'equipement': '',
        'AdresseIP': 'Unknown',
        'Fabricant': 'Unknown',
        'Fonction': 'Unknown',
        'Role': 'Unknown',
        'Version': 'Unknown',
        'SerialNumber': '',
        'EvaluationLicenseExpires': '',
        'Addressemac': '',
    }

    # Match hostname
    match_hostname = re.search(r'hostname\s+(\S+)', file_content, re.IGNORECASE)
    if match_hostname:
        info['equipement'] = match_hostname.group(1)

    # Match version
    match_version = re.search(r'version\s+(\S+)', file_content, re.IGNORECASE)
    if match_version:
        info['Version'] = match_version.group(1)
    # Match serial number
    match_serial = re.search(r'Serial number\s+(\S+)', file_content, re.IGNORECASE)
    if match_serial:
        info['SerialNumber'] = match_serial.group(1)


    # Match MAC address
    match_mac = re.search(r'Hardware is \S+, address is ([0-9A-Fa-f.]+)', file_content)
    if match_mac:
        info['Addressemac'] = match_mac.group(1).replace('.', ':')

    # Determine function and role
    content_lower = file_content.lower()
    if 'firewall' in content_lower:
        info['Fonction'] = 'Sécurité'
        info['Role'] = 'Firewall'
    elif 'switch' in content_lower:
        info['Fonction'] = 'Réseau'
        info['Role'] = 'Switch'
    elif 'router' in content_lower:
        info['Fonction'] = 'Réseau'
        info['Role'] = 'Routeur'
    elif 'wifi' in content_lower:
        info['Fonction'] = 'Réseau'
        info['Role'] = 'Wifi'

    # Determine manufacturer
    if 'cisco' in content_lower:
        info['Fabricant'] = 'Cisco'
    elif 'fortinet' in content_lower:
        info['Fabricant'] = 'Fortinet'
    elif 'aruba' in content_lower:
        info['Fabricant'] = 'Aruba'
    elif 'sophos' in content_lower:
        info['Fabricant'] = 'Sophos'

    # Print info to console
    print("Processed tech support file:")
    for key, value in info.items():
        print(f"{key}: {value}")

    return info

# Route to handle file upload and process tech support
@app.route('/process_tech_support', methods=['POST'])
def process_tech_support_route():
    if 'file' not in request.files:
        return jsonify({"message": "No file part in the request"})

    file = request.files['file']

    if file.filename == '':
        return jsonify({"message": "No file selected for uploading"})

    # Ensure the uploaded file is a .txt file
    if file and allowed_file(file.filename):
        try:
            file_content = file.read().decode('utf-8')
            info = process_tech_support_file(file_content)

            # Render a template with the extracted info
            return render_template('tech_support.html', info=info)

        except Exception as e:
            return jsonify({"message": f"Error processing file: {e}"})

    return jsonify({"message": "Invalid file format"})

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt'}

# Flask routes for rendering templates
@app.route('/')
def index():
    projects = list_projects()
    return render_template('index.html', projects=projects)

@app.route('/project/<project_id>/nodes')
def project_detail(project_id):
    nodes = list_nodes(project_id)
    return render_template('project_detail.html', nodes=nodes, project_id=project_id)

@app.route('/node_details/<project_id>/<node_id>')
def node_details(project_id, node_id):
    node_details = get_node_details(project_id, node_id)
    if not node_details:
        return "Node details not found."
    return render_template('node_detail.html', node=node_details, project_id=project_id, node_id=node_id)

@app.route('/retrieve_config/<node_ip>/<ssh_port>/<username>/<password>', methods=['GET'])
def retrieve_config_route(node_ip, ssh_port, username, password):
    try:
        ssh_port = int(ssh_port)
    except ValueError:
        return "Invalid port number."

    print(f"Attempting to retrieve configuration from {node_ip}:{ssh_port} via SSH...")
    success, tech_support_filename = retrieve_config(node_ip, ssh_port, username, password)
    if success:
        with open(tech_support_filename, 'r') as f:
            tech_support_content = f.read()
            info = process_tech_support_file(tech_support_content)
            return render_template('tech_support.html', info=info)
    else:
        return jsonify({"message": "Failed to retrieve configuration."})

if __name__ == '__main__':
    app.run(debug=True)
