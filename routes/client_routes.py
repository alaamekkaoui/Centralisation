# Import necessary modules and definitions
import getpass
import os
from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from models.client import Client
from models.equipment import Equipment
from services.ssh_service import get_node_details, list_nodes, list_projects, ping,process_tech_support_file, retrieve_config
from flask import flash
import subprocess 

client_bp = Blueprint('client_bp', __name__)

# Client routes
@client_bp.route('/clients', methods=['GET'])
def get_clients():
    clients = Client.get_all_clients()
    print("Clients:", clients)  # Print clients for debugging
    return render_template('clients.html', clients=clients)

@client_bp.route('/client/<client_name>', methods=['GET'])
def get_client(client_name):
    client = Client.get_client_by_name(client_name)
    if client:
        print("Client found:", client.name)
        print("Client equipment:", client.equipment) 
        return render_template('client_detail.html', client=client, Equipment=Equipment)
    else:
        print(f"Client '{client_name}' not found")  
        return jsonify({'error': 'Client not found'}), 404

@client_bp.route('/new_client', methods=['GET', 'POST'])
def new_client():
    if request.method == 'POST':
        client_data = request.form.to_dict()
        print("Received client data:", client_data)  
        client_id, _ = Client.get_or_create_client(client_data)
        return redirect(url_for('client_bp.get_clients'))
    else:
        return render_template('new_client.html')

@client_bp.route('/client/<client_name>/update', methods=['GET', 'POST'])
def update_client(client_name):
    if request.method == 'POST':
        update_data = request.form.to_dict()
        print("Update data:", update_data)  
        Client.update_client(client_name, update_data)
        return redirect(url_for('client_bp.get_clients'))
    else:
        client = Client.get_client_by_name(client_name)
        if client:
            print("Client found for update:", client.name)  
            return render_template('update_client.html', client=client)
        else:
            print(f"Client '{client_name}' not found for update")  # Print error message for debugging
            return jsonify({'error': 'Client not found'}), 404

@client_bp.route('/delete_client/<client_name>', methods=['GET', 'POST', 'DELETE'])
def delete_client(client_name):
    if request.method == 'POST' or request.method == 'DELETE':
        Client.delete_client(client_name)
        print(f"Deleted client: {client_name}")  # Print deleted client name for debugging
        return redirect(url_for('client_bp.get_clients'))
    else:
        return render_template('delete_client.html', client_name=client_name)

# Equipment routes

@client_bp.route('/client/<client_name>/new_equipment', methods=['GET', 'POST'])
def new_equipment(client_name):
    if request.method == 'POST':
        equip_data = request.form.to_dict()
        print("Received equipment data:", equip_data)  # Print received equipment data for debugging
        equip_id = Equipment.create_equipment(equip_data)
        client = Client.get_client_by_name(client_name)
        
        if client:
            client.add_equipment(equip_id)
            print(f"Added equipment '{equip_id}' to client '{client_name}'") 
            print("Updated client equipment:", client.equipment)
            return redirect(url_for('client_bp.get_client', client_name=client_name))
        else:
            print(f"Client '{client_name}' not found when adding equipment")  # Print error message for debugging
            return jsonify({'error': 'Client not found'}), 404
    else:
        client = Client.get_client_by_name(client_name)
        if client:
            print("Client found for new equipment:", client.name)  # Print client name for debugging
            return render_template('new_equipment.html', client_name=client.name)
        else:
            print(f"Client '{client_name}' not found for new equipment")  # Print error message for debugging
            return jsonify({'error': 'Client not found'}), 404

@client_bp.route('/client/<client_name>/update_equipment/<equip_id>', methods=['GET', 'POST'])
def update_equipment(client_name, equip_id):
    if request.method == 'POST':
        update_data = request.form.to_dict()
        print("Update data:", update_data)  # Print update data for debugging
        Equipment.update_equipment(equip_id, update_data)
        return redirect(url_for('client_bp.get_client', client_name=client_name))
    else:
        client = Client.get_client_by_name(client_name)
        if client:
            equipment = Equipment.get_equipment_by_id(equip_id)
            if equipment:
                print(f"Found equipment '{equip_id}' for client '{client_name}'") 
                return render_template('update_equipment.html', client_name=client_name, equipment=equipment)
            else:
                print(f"Equipment '{equip_id}' not found for client '{client_name}'")  
                return jsonify({'error': 'Equipment not found'}), 404
        else:
            print(f"Client '{client_name}' not found for updating equipment") 
            return jsonify({'error': 'Client not found'}), 404

@client_bp.route('/client/<client_name>/delete_equipment/<equip_id>', methods=['GET', 'POST', 'DELETE'])
def delete_equipment(client_name, equip_id):
    if request.method == 'POST' or request.method == 'DELETE':
        Equipment.delete_equipment(equip_id)
        client = Client.get_client_by_name(client_name)
        if client:
            client.remove_equipment(equip_id)
            print(f"Deleted equipment '{equip_id}' for client '{client_name}'")  # Print deleted equipment for debugging
        return redirect(url_for('client_bp.get_client', client_name=client_name))
    else:
        return render_template('delete_equipment.html', client_name=client_name, equip_id=equip_id)

@client_bp.route('/client/<client_name>/equipment/<equip_id>/detail', methods=['GET', 'POST'])
def equipment_detail(client_name, equip_id):
    equipment = Equipment.get_equipment_by_id(equip_id)
    
    status = ping(equipment.ip_address)
    if not equipment:
        print(f"Equipment '{equip_id}' not found for client '{client_name}'") 

        return jsonify({'error': 'Equipment not found'}), 404
    
    tech_support_info = process_tech_support_file(equipment.name)  

    print(tech_support_info)
    print(f"{equipment.ip_address}status:", status)
    return render_template('equipment_detail_page.html', status = status,client_name=client_name, equipment=equipment, tech_support_info=tech_support_info)

@client_bp.route('/access_console/<client_name>/equipment/<equip_id>/<host>/<ip_address>')
def access_console(client_name, equip_id, host, ip_address):
    ssh_port = 22

    equipment = Equipment.get_equipment_by_id(equip_id)
    print("Equipment:",equipment)
    if equipment:
        ssh_command = f'putty -ssh {ip_address} -P {ssh_port} -l {host}'
        try:
            subprocess.Popen(ssh_command, shell=True)
            flash('SSH console opened successfully.', 'success')
        except Exception as e:
            flash(f'Failed to open SSH console: {e}', 'danger')
    else:
        flash('Equipment not found.', 'danger')
    
    return redirect(url_for('client_bp.equipment_detail', client_name=client_name, equip_id=equip_id))

from flask import send_file

@client_bp.route('/retrieve_config/<client_name>/equipment/<equip_id>', methods=['GET'])
def retrieve_config_route(client_name, equip_id):
    client = Client.get_client_by_name(client_name)
    if not client:
        return jsonify({"message": "Client not found."}), 404

    equipment = Equipment.get_equipment_by_id(equip_id)
    if not equipment:
        return jsonify({"message": "Equipment not found."}), 404

    username = equipment.name
    password = equipment.password

    success, combined_output_file, _ = retrieve_config(equipment.ip_address, 22, username, password)

    if success:
        try:
            with open(combined_output_file, 'r') as file:
                file_content = file.read()
            tech_support_data = process_tech_support_file(file_content)
            return jsonify({"status": "success", "tech_support_data": tech_support_data})
        except Exception as e:
            return jsonify({"message": "Failed to process tech support data."}), 500
    else:
        return jsonify({"message": "Failed to retrieve configuration."}), 500
    

@client_bp.route('/retrieve_config/<client_name>/equipment/<equip_id>/download', methods=['GET'])
def download_config(client_name, equip_id):
    client = Client.get_client_by_name(client_name)
    if not client:
        return jsonify({"message": "Client not found."}), 404

    equipment = Equipment.get_equipment_by_id(equip_id)
    if not equipment:
        return jsonify({"message": "Equipment not found."}), 404

    username = equipment.name
    password = equipment.password

    success, tech_support_filename, _ = retrieve_config(equipment.ip_address, 22, username, password)

    if success:
        if os.path.exists(tech_support_filename):
            try:
                return send_file(tech_support_filename, as_attachment=True, download_name='tech_support.txt')
            except Exception as e:
                return jsonify({"message": "Failed to process file."}), 500
        else:
            return jsonify({"message": "File does not exist."}), 404
    else:
        return jsonify({"message": "Failed to retrieve configuration."}), 500


# --------------------------------------------------------------GNS3 Routes----------------------------------------
@client_bp.route('/client/gns3', methods=['GET'])
def show_gns3_nodes():
    project_name = 'Aarch'  # Replace with the actual project name if different
    
    # Fetch all projects
    projects = list_projects()
    
    # Find the project ID for the specified project name
    project_id = next((project['project_id'] for project in projects if project['name'] == project_name), None)
    
    if not project_id:
        return jsonify({'error': f'Project "{project_name}" not found in GNS3.'}), 404
    
    nodes = list_nodes(project_id)
    
    equipment_data = [
        {
            'node_id': node['node_id'],
            'name': node['name'],
            'node_type': node['node_type'],
            'status': node['status']
        } for node in nodes
    ]
    client_data = {
        'name': 'gns3',
        'description': 'GNS3 Project Client',
        'equipment_count': len(equipment_data)
    }
    
    client_id, created = Client.get_or_create_client(client_data)
    
    if not created:
        Client.update_client('gns3', client_data)
    
    # Redirect to the equipment detail page for GNS3 client
    return redirect(url_for('client_bp.get_gns3_equipment_detail'))


@client_bp.route('/client/gns3/equipment', methods=['GET'])
    # Combine and deduplicate equipment based on name, preferring more detailed entries
def get_gns3_equipment_detail():
    project_name = 'Aarch'

    # Fetch GNS3 project details
    projects = list_projects()
    project = next((p for p in projects if p['name'] == project_name), None)

    if not project:
        return jsonify({'error': f'Project "{project_name}" not found in GNS3.'}), 404

    project_id = project['project_id']

    # Fetch nodes from GNS3
    nodes = list_nodes(project_id)

    # Fetch or create the "gns3" client in the database
    client = Client.get_client_by_name('gns3')
    if not client:
        client_data = {
            'name': 'gns3',
            'description': 'GNS3 Project Client',
            'equipment_count': len(nodes)
        }
        client_id, _ = Client.get_or_create_client(client_data)
        client = Client.get_client_by_name('gns3')

    # Prepare a list to store equipment details
    equipment = []

    # Iterate through nodes fetched from GNS3
    for node in nodes:
        node_id = node['node_id']
        node_details = get_node_details(project_id, node_id)

        if node_details:
            node['details'] = node_details  # Attach details to node

        equipment.append(node)

        # Create or update equipment using Equipment model
        Equipment.create_or_update_equipment(node_id, {
            'name': node['name'],
            'equipment_type': node['node_type'],
            'ip_address': node_details.get('console_host', None),
            'client_id': client._id
        })

    # Fetch equipment details from the database using Equipment model
    db_equipment = Equipment.get_all_equipment_for_client(client._id)

    combined_equipment = {}
    
    for equip in equipment:
        name = equip['name']
        if name not in combined_equipment or (equip.get('details') and not combined_equipment[name].get('details')):
            combined_equipment[name] = equip
    
    for db_equip in db_equipment:
        name = db_equip['name']
        if name not in combined_equipment or (db_equip.get('details') and not combined_equipment[name].get('details')):
            combined_equipment[name] = db_equip
    
    combined_equipment = list(combined_equipment.values())

    return render_template('gns3_equipment_detail.html', client=client, equipment=combined_equipment)




