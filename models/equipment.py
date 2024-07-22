from services.ssh_service import ping
from utils.db import connect_to_mongodb as mongo
from bson.objectid import ObjectId
import ping3

class Equipment:
    def __init__(self, _id=None, name=None, host=None,description=None, password=None, equipment_type=None, ip_address=None, client_id=None , ping_status = None):
        self._id = _id
        self.name = name
        self.host = host
        self.password = password
        self.description = description
        self.equipment_type = equipment_type
        self.ip_address = ip_address
        self.client_id = client_id
        self.ping_status = ping_status 

    def ping(ip_address):
        try:
            # Perform ping with a timeout of 2 seconds
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

    @staticmethod
    def get_all_equipment():
        _, _, _, equipment_collection = mongo()
        equipment_list = list(equipment_collection.find())
        for equipment in equipment_list:
            equipment['ping_status'] = ping(equipment['ip_address'])         
        return equipment_list

    @staticmethod
    def get_equipment_by_id(equip_id):
        _, _, _, equipment_collection = mongo()
        equipment_data = equipment_collection.find_one({"_id": ObjectId(equip_id)})
        if equipment_data:
            equipment_data['_id'] = str(equipment_data['_id'])  # Convert ObjectId to string for easier usage
            equipment_data['ping_status'] = ping(equipment_data['ip_address'])
            return Equipment(**equipment_data)
        else:
            return None

    @staticmethod
    def get_equipment_by_name(client_name, equipment_name):
        _, _, _, equipment_collection = mongo()
        equipment_data = equipment_collection.find_one({"client_id": client_name, "name": equipment_name})
        if equipment_data:
            equipment_data['ping_status'] = ping(equipment_data['ip_address'])
            return Equipment(**equipment_data)
        else:
            return None

    @staticmethod
    def create_equipment(equip_data):
        _, _, _, equipment_collection = mongo()
        
        password = equip_data.pop('password', None)
        
        if password:
            equip_data['password'] = password  # Store password in equipment data
            
        equip_id = equipment_collection.insert_one(equip_data).inserted_id
        return str(equip_id)

    @staticmethod
    def update_equipment(equip_id, update_data):
        _, _, _, equipment_collection = mongo()
        equipment_collection.update_one({"_id": ObjectId(equip_id)}, {"$set": update_data})

    @staticmethod
    def delete_equipment(equip_id):
        _, _, _, equipment_collection = mongo()
        return equipment_collection.delete_one({"_id": ObjectId(equip_id)})

    @staticmethod
    def create_or_update_equipment(node_id, equip_data):
        _, _, _, equipment_collection = mongo()
        existing_equipment = equipment_collection.find_one({"node_id": node_id})
        if existing_equipment:
            equipment_collection.update_one({"node_id": node_id}, {"$set": equip_data})
        else:
            equip_data['node_id'] = node_id
            equipment_collection.insert_one(equip_data)

    @staticmethod
    def get_all_equipment_for_client(client_id):
        _, _, _, equipment_collection = mongo()
        return list(equipment_collection.find({"client_id": client_id}))
