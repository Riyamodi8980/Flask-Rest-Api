from flask import Flask, request, jsonify
from pymongo import MongoClient
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash , check_password_hash
from functools import wraps
from bson.objectid import ObjectId

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

client = MongoClient('mongodb://localhost:27017/')
db = client['details']
clientcred = db['client_credentials']


def encode_token(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=2)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def decode_token(token):
    try:
        payload= jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=request.headers['Authorization']

        if not token:
            return jsonify({"msg":"Token is missing"})
        
        try :
            payload=decode_token(token)
        except:
            return jsonify({"msg":"Token is Invalid"})    
        
        return f(*args,**kwargs)
    return decorated

@app.route('/register',methods=['POST'])
def register():
    _json=request.json
    
    if _json and request.method=="POST":
        _usrname=_json["username"]
        _pass=_json["password"]
        user=clientcred.find_one({"username":_usrname})
        if user:
            return jsonify({"Msg":"Client already registered"})
        
        hashed_password=generate_password_hash(_pass)
        clientcred.insert_one({"username":_usrname,"password":hashed_password})
        return jsonify({"Msg":"Registered.."})
    
    return jsonify({'Missing': 'username or password'})

@app.route("/login",methods=["POST"])
def login():
    _json=request.json
    
    if _json:
        _usrname=_json["username"]
        _pass=_json["password"]
        user=clientcred.find_one({"username":_usrname})

        if user and check_password_hash(user['password'],_pass):
            return jsonify({"Token":encode_token(_usrname)})
        
    
    return jsonify({'Msg': 'Invalid username or password'})

@app.route("/")
def home():
    return "Home Page"

@app.route("/books",methods=['GET'])
@token_required
def all_books():
    books=list(db.books.find())
    return jsonify({"books":books})

@app.route("/book/<bookid>",methods=['GET'])
@token_required
def get_book(book_id):
    book= db.books.find_one({"_id":ObjectId(book_id) })
    if not book:
        return jsonify({"msg":"book not found"})
    
    return jsonify({"books":book})

@app.route("/book",methods=['POST'])
@token_required
def add_book():
    title = request.json.get('title')
    author = request.json.get('author')
    genre = request.json.get('genre')

    # Insert the book into the database
    book_id = db.books.insert_one({'title': title, 'author': author, 'genre': genre}).inserted_id

    return jsonify({'message': 'Book added successfully', 'book_id': str(book_id)}), 201

@app.route("/book/<bookid>",methods=['PUT'])
@token_required
def update(book_id):
    

    # Insert the book into the database
    book = db.books.find_one({"_id":ObjectId(book_id)})
    if not book:
        return jsonify({'message': 'Book not found'})
    
    book["title"] = request.json.get('title')
    book["author"] = request.json.get('author')
    book["genre"] = request.json.get('genre')

    db.books.update_one({"_id":ObjectId(book_id)},{"$set":book})


    return jsonify({'message': 'Book updated successfully'})

@app.route('/book/<book_id>', methods=['DELETE'])
@token_required
def delete_book(book_id):
    # Delete the book from the database
    result = db.books.delete_one({'_id': ObjectId(book_id)})
    if result.deleted_count == 0:
        return jsonify({'message': 'Book not found'})
    return jsonify({'message': 'Book deleted successfully'})


if __name__ == "__main__":
    app.run(debug=True)
