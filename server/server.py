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
    try:
        contact_bloom_filter = BloomFilter.deserialise(cbf)
        query_bloom_filter = BloomFilter.deserialise(qbf)
        result = contact_bloom_filter & query_bloom_filter
        return True if 1 in result else False
    except:
        return False

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
    # print("DATA: ")
    # print(data)
    cbf = data['CBF']

    cbf_json = {
        'date': datetime.now().strftime("%m/%d/%Y"),
        'cbf': cbf
    }

    db = client['project']
    coll = db['cbf']
    coll.insert_one(cbf_json)

    print("\n********************************************************")
    print("Received user CBF, stored in database.\n")

    #TODO: Delete all after 21 days

    return make_response(
        dumps(
            {
                "result": "success",
            }
        ), 
        201
    ) 


@APP.route('/query', methods=['POST'])
def match():
    '''
    Matches QBF with CBF
    '''
    data = request.get_json()
    # print("DATA: ")
    # print(data)
    qbf = data['QBF']

    result = is_user_positive(qbf)

    print("\n********************************************************")
    print("Received user QBF, matching with all CBF's in the database")
    print(f"Were any matches found? {result}\n")

    return make_response(
        dumps(
            {
                "result": result,
            }
        ), 
        201
    ) 

if __name__ == "__main__":
    APP.run(port=(int(sys.argv[1]) if len(sys.argv) == 2 else 55000), debug=True)