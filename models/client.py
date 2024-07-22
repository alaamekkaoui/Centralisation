from utils.db import connect_to_mongodb as mongo
from bson.objectid import ObjectId

class Client:
    def __init__(self, _id=None, name=None, description=None, equipment=None, equipment_count=None):
        self._id = _id
        self.name = name
        self.description = description
        self.equipment = equipment if equipment else []
        self.equipment_count = equipment_count if equipment_count else len(self.equipment)

    @staticmethod
    def get_all_clients():
        _, _, clients_collection, _ = mongo()
        clients_data = list(clients_collection.find())
        clients_with_equipment_count = []
        
        for client_data in clients_data:
            client_data['_id'] = str(client_data['_id'])  # Convert ObjectId to string for easier usage
            client_data['equipment'] = [str(eid) for eid in client_data.get('equipment', [])]  # Convert ObjectId to string
            client_data['equipment_count'] = len(client_data.get('equipment', []))  # Calculate equipment count
            clients_with_equipment_count.append(Client(**client_data))
        
        return clients_with_equipment_count

    @staticmethod
    def get_client_by_name(client_name):
        _, _, clients_collection, equipment_collection = mongo()
        client_data = clients_collection.find_one({"name": client_name})
        
        if client_data:
            client_data['_id'] = str(client_data['_id'])  # Convert ObjectId to string for easier usage
            client_data['equipment'] = [str(eid) for eid in client_data.get('equipment', [])]  # Convert ObjectId to string
            client_data['equipment_count'] = len(client_data['equipment'])  # Calculate number of equipment
            return Client(**client_data)
        else:
            return None

    @staticmethod
    def get_or_create_client(client_data):
        _, _, clients_collection, _ = mongo()
        client_name = client_data.get("name")
        client = clients_collection.find_one({"name": client_name})

        if client:
            client_id = client["_id"]
            return client_id, False
        else:
            client_id = clients_collection.insert_one(client_data).inserted_id
            return client_id, True

    @staticmethod
    def update_client(client_name, update_data):
        _, _, clients_collection, _ = mongo()
        clients_collection.update_one({"name": client_name}, {"$set": update_data})

    @staticmethod
    def delete_client(client_name):
        _, _, clients_collection, equipment_collection = mongo()
        client = clients_collection.find_one({"name": client_name})
        
        if client and "equipment" in client:
            equipment_ids = [ObjectId(eid) for eid in client["equipment"]]
            equipment_collection.delete_many({"_id": {"$in": equipment_ids}})
        
        return clients_collection.delete_one({"name": client_name})

    def add_equipment(self, equip_id):
        _, _, clients_collection, _ = mongo()
        clients_collection.update_one({"_id": ObjectId(self._id)}, {"$push": {"equipment": ObjectId(equip_id)}})
        self.equipment.append(str(equip_id))  # Convert ObjectId to string for consistency

    def remove_equipment(self, equip_id):
        _, _, clients_collection, _ = mongo()
        clients_collection.update_one({"_id": ObjectId(self._id)}, {"$pull": {"equipment": ObjectId(equip_id)}})
        self.equipment.remove(str(equip_id))  # Convert ObjectId to string for consistency
