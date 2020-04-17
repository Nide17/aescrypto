from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode

from flask import Flask, render_template, request, flash
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
            
            # An initialization vector (IV) is an arbitrary number that can be used along with a 
            # secret key for data encryption. 
            # This number, also called a nonce, is employed only one time in any session.

            iv = b64encode(cipher.iv).decode('utf-8')

            ct = b64encode(ct_bytes).decode('utf-8')

            flash("Encrypted Successfully!", "msgOK")
            
            return render_template('indexofb.html', ct=ct)
            

        if request.form.get("encrypted"):    
            
            # Let's assume that the key was securely shared beforehand
                
            iv = b64decode(iv)

            ct = b64decode(request.form.get("encrypted"))

            cipher = AES.new(key, AES.MODE_OFB, iv=iv)

            original_message = cipher.decrypt(ct).decode()
            
            if original_message:

                flash("Decrypted Successfully!", "msgOK")

                return render_template('indexofb.html', original_message=original_message)
            
            else:
                
                flash("Error! Input are either not in this session or invalid at all!", "msgNotOK")
            
    return render_template('indexofb.html')        
            
    
