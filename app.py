from functools import wraps
import uuid

from flask import Flask, g, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash , check_password_hash

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(80),unique = True, nullable = False)
    password = db.Column(db.String(256),nullable = False)
    
class Session(db.Model):
    session_id = db.Column(db.String(256),primary_key = True)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'), nullable = False)
    created_at = db.Column(db.DateTime,default = datetime.utcnow())
    expire_at = db.Column(db.DateTime,nullable = False)
    

with app.app_context():
    db.create_all()
    
def login_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        session_id = request.cookies.get('session_id')
        if not session_id:
            return jsonify({'message' : 'Missing Session'})
        
        session = Session.query.filter_by(session_id=session_id).first()
        
        if not session or session.expire_at < datetime.utcnow():
            return jsonify({'message' : 'Invalid Session'}), 401
        
        g.user_id = session.user_id
        
        return f(*args,**kwargs)
    return decorated
        
        
    
@app.route('/register',methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    
    exist_user = User.query.filter_by(username=username).first()
    if exist_user:
        return jsonify({'message' : 'User already registered'})
    
    password_hash = generate_password_hash(password)
        
    new_user = User(username=username , password=password_hash)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'User registered successfully'}), 201

@app.route('/login',methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message' : 'Invalid Username'}), 401
    
    if not check_password_hash(user.password,password):
        return jsonify({'message' : 'Invalid Password'}), 401
    
    session_id = str(uuid.uuid4())
    expire_at = datetime.utcnow() + timedelta(minutes=5)
    
    new_session = Session(session_id=session_id,user_id=user.id,expire_at=expire_at)
    db.session.add(new_session)
    db.session.commit()
    
    response = make_response(jsonify({'message' : 'Login Successful'}),200)
    response.set_cookie('session_id',session_id,expires=expire_at,httponly=True)
    return response


@app.route('/profile',methods=['GET'])
@login_required
def profile():
    user = User.query.get(g.user_id)
    return jsonify({'message' : 'User Profile' , "username" : user.username}), 200

@app.route('/logout',methods=['GET'])
@login_required
def logout():
    session_id = request.cookies.get('session_id')
    session = Session.query.filter_by(session_id=session_id).first()

    if session:
        db.session.delete(session)
        db.session.commit()
        
    response = make_response(jsonify({'message' : 'Logout Successful'}))
    response.delete_cookie('session_id')
    return response
    
    
if __name__ == "__main__":
    app.run(debug=True)
