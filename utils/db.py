from pymongo import MongoClient

# Modify the MongoDB URI and database name as needed
MONGO_URI = 'mongodb+srv://demon:demon@cluster0.fbkw7gh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
DB_NAME = 'Client_DB'

client = None
db = None
clients_collection = None
equipment_collection = None

def connect_to_mongodb():
    global client, db, clients_collection, equipment_collection
    
    if client is None:
        try:
            # Attempt MongoDB connection
            client = MongoClient(MONGO_URI)
            db = client[DB_NAME]
            clients_collection = db['clients']  # Adjust collection names as per your schema
            equipment_collection = db['equipment']
            print(f"Connected to MongoDB, Database '{DB_NAME}'")
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")

    return client, db, clients_collection, equipment_collection
