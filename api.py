import re
import datetime
import functools
import pymongo
import json
import jwt
import requests
from flask import jsonify
from pymongo import MongoClient
from flask import Flask, request
from flask_mail import Mail, Message
from flask_restful import Resource, Api, abort
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
api = Api(app)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'emailmu@mail.com'
app.config['MAIL_PASSWORD'] = '***********'
app.config['MAIL_DEFAULT_SENDER'] = 'yourmail@contoh.com'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['ACTIVATION_EXPIRE_DAYS'] = 5
app.config['TOKEN_EXPIRE_HOURS'] = 1
app.config['KEY'] = 'secret'

mail = Mail(app)
uri = ("mongodb://localhost:27017/api")
client = MongoClient(uri)
db = client.api

def token_required(method):
	@functools.wraps(method)
	def wrapper(self):
		header = request.headers.get('Authorization')
		_, token = header.split()
		try:
			decoded = jwt.decode(token, app.config['KEY'], algorithms='HS256')
		except jwt.DecodeError:
			abort(400, message='Token is not valid.')
		except jwt.ExpiredSignatureError:
			abort(400, message='Token is expired.')
		email = decoded['email']
		if db.users.find({'email': email}).count() == 0:
			abort(400, message='User is not found.')
		user = db.users.find_one({'email': email})
		return method(self, user)
	return wrapper

class Register(Resource):
	@token_required
	def post(self):
		email = request.json['email']
		password = request.json['password']
		if not re.match(r'^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email):
			abort(400, message='email is not valid.')
		if len(password) < 6:
			abort(400, message='password is too short.')
		if db.users.find({'email': email}).count() != 0:
			if db.users.find_one({'email': email})['active'] == True:
				abort(400, message='email is alread used.')
		else:
			db.users.insert_one({'email': email, 'password': generate_password_hash(password), 'active': False})
		exp = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['ACTIVATION_EXPIRE_DAYS'])
		encoded = jwt.encode({'email': email, 'exp': exp},
							 app.config['KEY'], algorithm='HS256')
		message = 'Hello\nactivation_code={}'.format(encoded.decode('utf-8'))
		msg = Message(recipients=[email],
					  body=message,
					  subject='Activation Code')
		mail.send(msg) 
		return jsonify({'message': 'Data Berhasil Ditambahkan check email untuk validasi Token!'})

class Activate(Resource):
	@token_required
	def put(self):
		activation_code = request.json['activation_code']
		try:
			decoded = jwt.decode(activation_code, app.config['KEY'], algorithms='HS256')
		except jwt.DecodeError:
			abort(400, message='Activation code is not valid.')
		except jwt.ExpiredSignatureError:
			abort(400, message='Activation code is expired.')
		email = decoded['email']
		db.users.update({'email': email}, {'$set': {'active': True}})
		return jsonify({'message': 'Data Berhasil Divalidasi..!!!'})

		
class Login(Resource):
	@token_required
	def get(self):
		email = request.json['email']
		password = request.json['password']
		if db.users.find({'email': email}).count() == 0:
			abort(400, message='User is not found.')
		user = db.users.find_one({'email': email})
		if not check_password_hash(user['password'], password):
			abort(400, message='Password is incorrect.')
		exp = datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['TOKEN_EXPIRE_HOURS'])
		encoded = jwt.encode({'email': email, 'exp': exp},
							 app.config['KEY'], algorithm='HS256')
		return {'email': email, 'token': encoded.decode('utf-8')}


class Delete(Resource):
	@token_required
	def delete(self):
		email = request.json['email']
		if db.users.find({'email': email}).count() == 0:
			abort(400, message='User is not found.')
		user = db.users.find_one({'email': email})
		db.users.remove({'email': email})
		
		return jsonify({'message': 'Berhasil Dihapus..!!!'})
	
api.add_resource(Register, '/v1/register')
api.add_resource(Activate, '/v1/activate')
api.add_resource(Login, '/v1/login')
api.add_resource(Delete, '/v1/delete')
if __name__ == '__main__':
	app.run(host="0.0.0.0", port=5000)