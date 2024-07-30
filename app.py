from flask import Flask, redirect, render_template, url_for
from routes.client_routes import client_bp 
from routes.ssh_routes import ssh_bp
from utils.db import connect_to_mongodb
from routes.nipper_routes import nipper_bp  # Import the nipper blueprint

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

client, db, clients_collection, equipment_collection = connect_to_mongodb()

app.config['MONGO_CLIENT'] = client
app.config['MONGO_DB'] = db
app.config['USERS_COLLECTION'] = clients_collection

# Register Blueprints
app.register_blueprint(client_bp)
app.register_blueprint(ssh_bp)
app.register_blueprint(nipper_bp)

@app.route("/")
def index():
    return redirect(url_for('client_bp.get_clients'))

if __name__ == '__main__':
    app.run(debug=True,port=5001)
