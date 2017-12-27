import os
from flask import Flask, jsonify, request, make_response
from itsdangerous import JSONWebSignatureSerializer
import datetime
import jwt 
import pdb
from functools import wraps
app = Flask(__name__)
import onetimepass as otp
app.config['SECRET_KEY'] = str(JSONWebSignatureSerializer(os.urandom(24)))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('token') 
        #print token

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
			
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated
	

@app.route('/login', methods=['POST'])
def login():
    authentication =  request.get_json(force=True) 
    if authentication['user'] == "guest" and authentication['password'] == "Thr3@tSc0r3":
        token = jwt.encode({'user' : authentication['user'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=300)}, app.config['SECRET_KEY'])
        return jsonify(token = token.decode('UTF-8'),msg = "authentication Success",HTTP_Status_Code = 200)
    return jsonify(msg = "authentication Failure",HTTP_Status_Code = 200)

	
@app.route('/threat_score_submission_sample',methods=['POST'])
@token_required
def threat_score_submission_sample():
    register = request.get_json( force = True)
    if register['aggregator']=="" or register['legal']=="" or register['firstname']=="" or register['lastname']=="" or register['email']=="" or  register['phone']=="" or register['campaignid']=="" or register['campaigntype']=="" or  register['phonenumber']=="" or register['campaignsendingrate']=="" or register['numberpools']=="":
        return jsonify({'message' : 'Any of the mandatory value is missing, please verify.'}) , 400
	
    return jsonify({'message' : 'validation data form submitted succesfully'})

if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 80,threaded = True)
