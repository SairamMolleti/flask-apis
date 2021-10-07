from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager, jwt_required
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

client = MongoClient()
db = client.data

@app.route('/create_user/', methods = ["POST"])
def create_user():
    data = request.get_json()
    if data['username'] != '' and len(data['password']) >= 6:
        hashedPassword = bcrypt.generate_password_hash(data['password'])
        data['password'] = hashedPassword
        db.table.insert_one(data)
        return jsonify({
            'message': 'success'
        })
    else:
        return jsonify({
            'message': 'failed'
        })

@app.route('/login/', methods = ["POST"])
def login_user():
    access_token = create_access_token(identity="example_user")
    return jsonify(access_token=access_token)


@app.route('/edit_user/', methods = ["PUT"])
@jwt_required()
def edit_user():
    data = request.get_json()
    if len(data['password']) >= 6:
        print(data['password'])
        hashed_password = bcrypt.generate_password_hash(data['password'])
        data['password'] = hashed_password
        db.table.update(
            {'username': data['username']}, 
            { "$set" : {'password': data['password']}}
        )
        return jsonify({
            "message": 'success'
        })
    else: 
        return jsonify({
            "message": 'password too short'
        })


@app.route('/delete_user/', methods = ["DELETE"])
@jwt_required()
def delete_user():
    data = request.get_json()
    db.table.remove({'username': data['username']})
    return jsonify({'message': 'deleted success'})

@app.route('/test_db/')
def test_db():
    for item in db.table.find():
        print(item)
    return jsonify({'message': 'succuss'})

app.run()