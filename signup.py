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
