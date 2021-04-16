from flask import Flask, request, redirect, url_for
from flask_cors import CORS
from flask.helpers import make_response
from json import dumps
import sys
from datetime import datetime, timedelta
from pymongo import MongoClient

try:
    from ..DIMY import BloomFilter
except:
    print(sys.path)
    from BloomFilter import BloomFilter

APP = Flask(__name__)
# Allows cross-origin AJAX, so React can talk to this API
CORS(APP)

# Connect to MongoDB
connection_string = "mongodb+srv://comp4337:comp4337@cluster0.mzbuz.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
client = MongoClient(connection_string)

def is_match(qbf, cbf):
    '''
    Given a cbf and qbf
    returns true if a match
    returns false otherwise
    '''
    contact_bloom_filter = BloomFilter.deserialise(cbf)
    query_bloom_filter = BloomFilter.deserialise(qbf)
    result = cbf & qbf
    return True if 1 in result else False

def is_user_positive(qbf):
    '''
    Server performing QBF-CBF matching
    '''
    today = datetime.now()

    # Get all cbf's from db
    db = client['project']
    coll = db['cbf']
    entries = coll.find({})
    for entry in entries:
        # Make sure date pf cbf within previous 21 days
        date = datetime.strptime(entry['date'], '%m/%d/%Y')
        cbf = entry['cbf']
        
        if (date < today + timedelta(days=21)):
            if (is_match(qbf, cbf)):
                return "matched"
    
    return "not matched"

@APP.route('/upload', methods=['POST'])
def upload():
    '''
    Stores CBF in database
    '''
    data = request.get_json()
    print("DATA: ")
    print(data)
    cbf = data['CBF']

    cbf_json = {
        'date': datetime.now().strftime("%m/%d/%Y"),
        'cbf': cbf
    }

    db = client['project']
    coll = db['cbf']
    coll.insert_one(cbf_json)

    print("Inserted cbf to backend server")

    return make_response(
        dumps(
            {
                "result": "success",
            }
        ), 
        201
    ) 


@APP.route('/match', methods=['POST'])
def match():
    '''
    Matches QBF with CBF
    '''
    data = request.get_json()
    print("DATA: ")
    print(data)
    qbf = data['QBF']

    result = is_user_positive(qbf)

    return make_response(
        dumps(
            {
                "result": result,
            }
        ), 
        201
    ) 

if __name__ == "__main__":
    APP.run(port=(int(sys.argv[1]) if len(sys.argv) == 2 else 2110), debug=True)