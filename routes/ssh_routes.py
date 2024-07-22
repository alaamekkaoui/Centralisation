from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from models.client import Client
from models.equipment import Equipment 
from services.ssh_service import list_projects, list_nodes, get_node_details, retrieve_config, process_tech_support_file , allowed_file
import os
from flask import flash

ssh_bp = Blueprint('ssh_bp', __name__)
@ssh_bp.route('/gns3')
def index():
    projects = list_projects()
    return render_template('gns3.html', projects=projects)

@ssh_bp.route('/project/<project_id>/nodes')
def project_detail(project_id):
    nodes = list_nodes(project_id)
    return render_template('project_detail.html', nodes=nodes, project_id=project_id)

@ssh_bp.route('/node_details/<project_id>/<node_id>')
def node_details(project_id, node_id):
    node_details = get_node_details(project_id, node_id)
    if not node_details:
        return "Node details not found."
    return render_template('node_detail.html', node=node_details, project_id=project_id, node_id=node_id)

@ssh_bp.route('/retrieve_config/<host>/<username>/<password>', methods=['GET'])
def retrieve_config_route(host,username, password):
    try:
        ssh_port = int(ssh_port)
    except ValueError:
        return "Invalid port number."

    print(f"Attempting to retrieve configuration from {username}:{host} via SSH...")
    success, tech_support_filename = retrieve_config(ssh_port, username, password)
    if success:
        with open(tech_support_filename, 'r') as f:
            tech_support_content = f.read()
            info = process_tech_support_file(tech_support_content)
            print("Extracted tech support info:", info)
            return render_template('tech_support.html', info=info)
    else:
        return jsonify({"message": "Failed to retrieve configuration."})

@ssh_bp.route('/process_tech_support', methods=['POST'])
def process_tech_support_route():
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'tech_old.txt')
        
        # Check if the file exists
        if not os.path.exists(file_path):
            return jsonify({"message": "File not found"}), 404
        
        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()
        
        # Process the file content
        info = process_tech_support_file(file_content)
        print("Extracted tech support info from ssh route:", info)
        # Return JSON response
        return jsonify(info)
    
    except Exception as e:
        return jsonify({"message": f"Error processing file: {e}"}), 500

@ssh_bp.route('/ping_devices')
def ping_devices_view():
    response = ping3()  
    return response