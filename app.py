from flask import Flask, request,jsonify,render_template
import psycopg2
from psycopg2 import sql
from flask_bcrypt import Bcrypt
import jwt
import datetime

app = Flask(__name__, template_folder='templates')


bcrypt = Bcrypt(app)

SECRET_KEY = "this is my secret key this is my secret key!!"


def create_jwt(user_id, username):
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm ="HS256")
    return token

def verify_jwt(token):
    data = jwt.decode(token,SECRET_KEY,algorithms =["HS256"])
    return data


#Database configurition
DB_HOST = 'localhost'
DB_NAME='postgres'
DB_USER='postgres'
DB_PASSWORD='1616'


def get_db_connection():
    connection= psycopg2.connect(
        host = DB_HOST,
        database = DB_NAME,
        user= DB_USER,
        password = DB_PASSWORD
    )
    return connection

def create_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
          CREATE TABLE IF NOT EXISTS user_db(
                   user_id SERIAL PRIMARY KEY,
                   username TEXT NOT NULL,
                   email TEXT NOT NULL UNIQUE,
                   password TEXT NOT NULL
                   );
""")
    connection.commit()
    cursor.close()
    connection.close()

def create_form_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
          CREATE TABLE IF NOT EXISTS student_forms (
            form_id SERIAL PRIMARY KEY,
            user_id INTEGER,
            full_name TEXT,
            age TEXT,
            course TEXT
                   );
""")
    connection.commit()
    cursor.close()
    connection.close()

create_table_if_not_exists()
create_form_table_if_not_exists()


@app.route("/")
def index():
    return render_template('login.html')

@app.route("/signup")
def signup():
    return render_template('signup.html')

@app.route("/dashboard")
def dashboard():
    return render_template('dashboard.html')

@app.route("/sigup", methods=['POST'])
def sigup():
   username= request.json['username']
   email = request.json['email']
   password = request.json['password']
   hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

   if not username or not email or not hashed_password:
       return({"error":"Missing fields"}),401
   connection = get_db_connection()
   cursor = connection.cursor()
   cursor.execute("""
           INSERT INTO user_db(username,email,password) VALUES(%s,%s,%s)
                  RETURNING user_id
""",(username,email,hashed_password))
   user_id = cursor.fetchone()[0]
   connection.commit()
   cursor.close()
   connection.close()
   token = create_jwt(user_id,username)
   return jsonify({
       "message":"user sigup successfully",
       "token":token
   })

@app.route("/login", methods = ['POST'])
def login():
   email = request.json['email']
   password = request.json['password']
   connection = get_db_connection()
   cursor = connection.cursor()
   cursor.execute("""
           SELECT user_id, username , password  FROM user_db where email =%s;
""",(email,))
   user = cursor.fetchone()
   connection.commit()
   cursor.close()
   connection.close()

   user_id , username, hashed_password = user
   if not bcrypt.check_password_hash(hashed_password,password):
       return jsonify({"error":"incorrect password"}),401
   

   token = create_jwt(user_id,username)
   return jsonify({
       "message":"user login successfully",
       "token":token,
       "user":{
            "user_id": user_id,
            "username": username,
            "email": email
       }
   }),201


@app.route("/apply",methods =['POST'])
def apply():
    token = request.headers.get("Authorization")

    if not token :
        return jsonify({"error":"token invaild"}),401
    user_data = verify_jwt(token)
    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    full_name =request.json['full_name']
    age =request.json['age']
    course = request.json['course']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
           INSERT INTO student_forms(user_id,full_name,age,course) VALUES (%s,%s,%s,%s);
                   
""",(user_data["user_id"],full_name, age,course))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"application submited"}),201

@app.route("/get_apply",methods =['GET'])
def get_apply():
    token = request.headers.get("Authorization")

    if not token :
        return jsonify({"error":"token invaild"}),401
    user_data = verify_jwt(token)

    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
           SELECT form_id,full_name,age,course FROM student_forms where user_id =%s;
                   
""",(user_data["user_id"],))
    user = cursor.fetchall()
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({
        "user":user_data["username"],
        "Form":[
            {
                "form_id":f[0],
                "fullname":f[1],
                "age":f[2],
                "course":f[3]
            } for f in user
        ]
    }),201


@app.route("/update_apply/<int:form_id>",methods =['PUT'])
def update_apply(form_id):
    token = request.headers.get("Authorization")

    if not token :
        return jsonify({"error":"token invaild"}),401
    user_data = verify_jwt(token)
    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    full_name =request.json['full_name']
    age =request.json['age']
    course = request.json['course']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            SELECT * FROM student_forms  where form_id =%s AND user_id =%s
""",(form_id,user_data['user_id']))
    cursor.fetchone()
    cursor.execute("""
           UPDATE student_forms SET full_name=%s,age=%s,course=%s
                   WHERE form_id=%s ;
                   
""",(full_name, age,course,form_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"application updated"}),201


@app.route("/delete_apply/<int:form_id>",methods =['DELETE'])
def delete_apply(form_id):
    token = request.headers.get("Authorization")

    if not token :
        return jsonify({"error":"token invaild"}),401
    user_data = verify_jwt(token)
    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            SELECT * FROM student_forms  where form_id =%s AND user_id =%s
""",(form_id,user_data['user_id']))
    cursor.fetchone()
    cursor.execute("""
           DELETE  FROM student_forms WHERE form_id=%s ;
                   
""",(form_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"Form deleted successfully"}),201



if __name__ == '__main__':
    app.run(debug=True)