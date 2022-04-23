from flask import Flask, render_template,url_for, request,redirect, flash,session,abort
import flask_sqlalchemy
import joblib
import numpy as np
import json
from functools import wraps
import pymongo
app = Flask(__name__)
app.secret_key = "super secret key"
import string
import pandas as pd
import numpy as np
import hashlib
import pymongo
from Cryptodome import Random
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode
from http import client
from unicodedata import category, name
from xml.etree.ElementInclude import include
from flask import Flask , jsonify
import uuid


mongo = pymongo.MongoClient(host="localhost",port=27017,serverSelectionTimeoutMS=10000)
print(mongo.server_info())
db = mongo.login
class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

class User:
    def signup(self):
        user={
            "userid":request.form.get("userid"),
            "password":request.form.get("password")
        }
        try:
            user['password']=AESCipher("prime").encrypt(str(user['password']))
            if db.users.find_one({ "userid": user['userid'] }):
                return render_template('signup.html',error_message="USER ID ALREADY EXISTS")
            responsedb=db.users.insert_one(user)
            if responsedb:
                return render_template('prediction.html')
        except pymongo.errors.DuplicateKeyError:
            return render_template('signup.html',error_message="USER ID ALREADY EXISTS")

@app.route('/')
def home():
        return render_template('login.html')


@app.route('/login/', methods = ['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        userid = request.form['userid']
        password = request.form['password']
        try:
            user = db.users.find_one({"userid": userid})
            if(not user):
                return render_template('login.html',error_message="WRONG USERNAME OR PASSWORD")
            pswd=AESCipher("prime").decrypt(user["password"])
            if (user and pswd==password):
                return render_template('prediction.html')
            return render_template('login.html',error_message="WRONG USERNAME OR PASSWORD")
        except ValueError:
            return render_template('login.html',error_message="WRONG USERNAME OR PASSWORD")


@app.route('/signup/', methods = ['GET','POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    if request.method == 'POST':
        return(User().signup())


@app.route('/prediction/', methods = ['POST','GET'])
def prediction():
    if request.method == 'POST':
        gender = request.form['gender']
        married = request.form['status']
        dependat =request.form['dependants']
        education = request.form['education']
        employ = request.form['employ']
        annual_income = request.form['aincome']
        co_income = request.form['coincome']
        Loan_amount = request.form['Lamount']
        Loan_amount_term = request.form['Lamount_term']
        credit = request.form['credit']
        proper = request.form['property_area']

    gender = gender.lower()
    married= married.lower()
    education = education.lower()
    employ = employ.lower()
    proper = proper.lower()
    error = 0
    if(employ=='yes'):
        employ = 1
    else:
        employ = 0
    if(gender=='male'):
        gender = 1
    else:
        gender = 0
    if (married=='married'):
        married=1
    else:
        married=0
    if (proper=='rural'):
        proper=0
    elif (proper=='semiurban'):
        proper=1
    else:
        proper=2
    if (education=='graduate'):
        education=0
    else:
        education=1
    try:
        dependat = int(dependat)
        annual_income = int(annual_income)
        co_income = int(co_income)
        Loan_amount = int(Loan_amount)
        Loan_amount_term = int(Loan_amount_term)
        credit = int(credit)
        x_app = np.array([[gender, married, dependat,education,employ,annual_income,co_income,Loan_amount,Loan_amount_term,credit,proper]])
        model = joblib.load('Forest.pkl')
        ans = model.predict(x_app)
        # if (ans==1):
        #     print("Congratulations your eligble for this Loan")
        # else:
        #     print("We sad to inform that your request has not been accepted")
        return render_template('output.html', prediction=ans)
    except ValueError:
        return render_template('output.html', prediction=0)
    

if __name__ == '__main__':
    app.run(debug=True)