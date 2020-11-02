"""
Python Rest API Secure Code
"""
import configparser
from flask import Flask, jsonify, abort, make_response, request
import pymysql
from cryptography.fernet import Fernet
from flask_httpauth import HTTPBasicAuth

AUTH = HTTPBasicAuth()

# Fernet key for decrypting password
KEY = b'wn4k6OcMOV59SMec89iJQQyLeu0pGIDp0bzCPohDkjg='
cipher_suite = Fernet(KEY)

config = configparser.RawConfigParser()
config.read('db.properties')

apiEncPass = config.get('AuthenticationSection', 'api.enc.passwd')

apiEncPass = str.encode(apiEncPass)

uncipherAPI_pass = (cipher_suite.decrypt(apiEncPass))
apiPass = uncipherAPI_pass.decode()


@AUTH.get_password
def get_password(username):
    """Check username and password to ensure access is permitted"""
    if username == 'restuser':
        return apiPass
    return None


@AUTH.error_handler
def unauthorized():
    """ Return error for unauthorized persons attempting rest API access"""
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


# Database properties from the external properties file
host = config.get('DatabaseSection', 'database.host')
user = config.get('DatabaseSection', 'database.user')
name = config.get('DatabaseSection', 'database.name')
password = config.get('DatabaseSection', 'database.enc.passwd')

ENCRYPTEDPWD = str.encode(password)

uncipher_pass = (cipher_suite.decrypt(ENCRYPTEDPWD))
password = uncipher_pass.decode()

# Database Connection
connection = pymysql.connect(host=host, user=user, passwd=uncipher_pass, database=name)
# Can use DB for queries
db = connection.cursor()

app = Flask(__name__)


@app.route('/get/all', methods=['GET'])
@AUTH.login_required()
def get_users():
    """Get all Users Method"""
    # Handle Parsing and SQL here
    retrieve = "SELECT * FROM USERS;"
    db.execute(retrieve)
    rows = db.fetchall()
    for row in rows:
        print(row)
    return jsonify({'users': rows})


@app.route('/get/single', methods=['POST'])
@AUTH.login_required()
def get_user():
    """ Get single user method """
    user_id = request.json.get('id')
    retrieve = "Select firstName, lastName, email from users where id = %s"
    db.execute(retrieve, (user_id,))
    rows = db.fetchall()
    for row in rows:
        print(row)

    return jsonify({'users': rows})


@app.route('/create/user', methods=['POST'])
@AUTH.login_required()
def create_user():
    """ Create a User method """
    firstname = request.json.get('firstName')
    lastname = request.json.get('lastName')
    email = request.json.get('email')
    if firstname is None or lastname is None:
        abort(400)  # Missing arguments from JSON

    # Function that checks if email already exist in the DB
    retrieve = "Select id from users where email = %s"
    db.execute(retrieve, (email,))
    rows = db.fetchone()
    if rows is not None:
        abort(403)

    insert = "INSERT INTO users(firstName, lastName, email) VALUES (%s, %s, %s)"

    db.execute(insert, (firstname, lastname, email))
    connection.commit()

    return jsonify({'firstName': firstname, 'lastName': lastname, 'Created': True}), 201


@app.route('/delete/user', methods=['POST'])
@AUTH.login_required()
def delete_user():
    """ Delete a user method """
    user_id = request.json.get('id')
    retrieve = "Delete from users where id = %s"
    db.execute(retrieve, (user_id,))
    connection.commit()

    # Handle Parsing and SQL here
    return jsonify({'id': user_id, 'Deleted': True}), 201


# Error Handling

@app.errorhandler(404)
def not_found(error):
    """ JSON 404 error handling """
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.errorhandler(403)
def already_exists(error):
    """ JSON 403 error handling """
    return make_response(jsonify({'error': 'User Already Exists'}), 403)


if __name__ == '__main__':
    app.run(debug=False)
