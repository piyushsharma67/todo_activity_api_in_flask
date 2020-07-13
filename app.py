from flask import Flask,request,jsonify,json,make_response
from flask_sqlalchemy import SQLAlchemy 
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import os
from flask_marshmallow import Marshmallow 
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,create_refresh_token,
    get_jwt_identity
)

app=Flask(__name__)
jwt=JWTManager(app)


basedir=os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///' + os.path.join(basedir,'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATION']=False 
app.config['JWT_SECRET_KEY']=os.urandom(60)
app.config['JWT_ACCESS_TOKEN_EXPIRES']=False

db=SQLAlchemy(app)
ma=Marshmallow(app)

class User(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	public_id=db.Column(db.String(200),unique=True)
	admin=db.Column(db.Boolean)
	name=db.Column(db.String(300),unique=True)
	password=db.Column(db.String(300))
	# blogs=db.relationship('Blog',backref='user')


	def __init__(self,public_id,name,password,admin):
		
		self.public_id=public_id
		self.name=name
		self.password=password
		self.admin=admin


class UserSchema(ma.SQLAlchemySchema):
	class Meta():
		model=User
	name=ma.auto_field()
	public_id=ma.auto_field()
userschema=UserSchema()
usersschema=UserSchema(many=True)


class Blog(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	activity=db.Column(db.Text)
	user_id=db.Column(db.Text)

	def __init__(self,activity,user_id):
		self.activity=activity
		self.user_id=user_id

class BlogSchema(ma.SQLAlchemySchema):
	class Meta():
		model=Blog
	activity=ma.auto_field()
	# user_id=ma.auto_field()
	
# blogschema=BlogSchema()
blogschema=BlogSchema(many=True)


@app.route('/users',methods=['GET'])
@jwt_required
def gets_all_user():
	header=request.headers
	print(header)

	user=User.query.all()
	result=usersschema.dump(user)
	return jsonify({"users":result})


@app.route('/particular_user/<name>',methods=['GET'])
def get_user(name):
	user=User.query.filter_by(name=name).first_or_404()
	result=userschema.dump(user)
	return jsonify({"user":result})



@app.route('/create_user',methods=['POST'])
def create_user():
	data=request.get_json()
	hashed_password=generate_password_hash(data['password'],method="sha256")
	db.create_all()
	new_user=User(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=False)
	db.session.add(new_user)
	db.session.commit()
	result=userschema.dump(new_user)				#Schema is a List of Dictionary
	return result


@app.route('/login',methods=['GET'])
def login():
	
	data=request.get_json()
	header=request.headers
	name1=data['name']
	password1=data['password']
	
	if not data or not name1 or not password1:
		return make_response("could not verify",401,{"WWW-Authenticate":'Basic-realm="Login required"'})
	user=User.query.filter_by(name=name1).first()
	

	if not user:
		return make_response("could not verify",401,{"WWW-Authenticate":'Basic-realm="Login required"'})

	if check_password_hash(user.password,password1):
		search_userid=User.query.filter_by(name=name1).first()
		user_id=search_userid.public_id		
		access_token=create_access_token(identity=user_id)
		refresh_token=create_refresh_token(identity=name1)
		
		return jsonify(access_token=access_token)

	return make_response("could not verify",401,{"www-Authenticate":'Basic-realm="Login required"'})



@app.route('/user/activity_create',methods=['POST'])
@jwt_required
def create_Blog():
	req=request.get_json()
	print(req)
	activity=req['activity']
	print(req)
	print(activity)
	user_id=get_jwt_identity()
	activity_obj=Blog(activity=activity,user_id=user_id)
	db.session.add(activity_obj)
	db.session.commit()
	return ({"activity_status":"successfully_added"})




@app.route('/user/activities',methods=["GET"])
@jwt_required
def user_activities():
	user_id=get_jwt_identity()
	print(user_id)
	act_obj=Blog.query.filter_by(user_id=user_id).all()
	print(act_obj)

	res=blogschema.dump(act_obj)
	print(res)
	return jsonify({"user_to_do_activities":res})


if (__name__=='__main__'):
	app.run(debug=True,port=8000)




