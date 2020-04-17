import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from base64 import b64decode
from Crypto.Util.Padding import unpad

from flask import Flask, session, redirect, render_template, request, flash, url_for
from flask_session import Session

app = Flask(__name__)

# Configure the session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

Session(app)

key = get_random_bytes(16)

@app.route('/', methods=["GET", "POST"])
def indexofb():
    
    if request.method == "POST":
        global iv
        
        if request.form.get("message"):

            data = bytes(request.form.get("message"), encoding='utf-8')

            cipher = AES.new(key, AES.MODE_OFB)

            ct_bytes = cipher.encrypt(data)

            iv = b64encode(cipher.iv).decode('utf-8')

            ct = b64encode(ct_bytes).decode('utf-8')


            # An initialization vector (IV) is an arbitrary number that can be used along with a 
            # secret key for data encryption. 
            # This number, also called a nonce, is employed only one time in any session.

            flash("Encrypted Successfully!", "msgOK")
            
            print ('The encrypted message is: ' + ct)
            
            return render_template('indexofb.html', ct=ct);
            

        if request.form.get("encrypted"):    
            
            # We assume that the key was securely shared beforehand

                
            iv = b64decode(iv)

            ct = b64decode(request.form.get("encrypted"))

            cipher = AES.new(key, AES.MODE_OFB, iv=iv)

            original_message = cipher.decrypt(ct).decode()

            # print("The message was: ", original_message)

            # ct = b64decode(bytes(request.form.get('encrypted')), encoding= 'utf-8')

            # if request.form.get("encrypted"):
            flash("Decrypted Successfully!", "msgOK")

            return render_template('indexofb.html', original_message=original_message);
                # print("The message was: ", original_message)
            
            # return render_template('indexofb.html', original_message=original_message, ct=ct);

            flash("Error in decryption!", "msgNotOK")
            # print("Error in decryption!")
            
    return render_template('indexofb.html')        
            
    
