from flask import Blueprint, jsonify

# Create a Blueprint for the app
main = Blueprint('main', __name__)

@main.route('/')
def home():
    return jsonify(message="Welcome to the Flask app!")

@main.route('/api/data')
def get_data():
    data = {
        "key1": "value1",
        "key2": "value2"
    }
    return jsonify(data)