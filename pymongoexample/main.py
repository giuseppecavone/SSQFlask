from flask import request, Blueprint, jsonify
import json
import datetime
from .extensions import mongo, flask_bcrypt, flask_jwt, flask_schedule
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                jwt_required, jwt_refresh_token_required, get_jwt_identity,
                                set_access_cookies,
                                set_refresh_cookies, unset_jwt_cookies)
import sys
import logging
from .user import validate_user
#from . import flask_bcrypt
main = Blueprint('main', __name__)

#cancello la collezione del giorno dopo, 5 minuti prima
@flask_schedule.task('cron', id='do_drop_collection', hour=23, minute=59, second='55')
def drop_collection():
    day=str(datetime.datetime.today().weekday())
    collection="SenseSquare7D_"+str(((day+1) % 7))
    mongo.db.drop_collection(collection)
    

@main.route('/send_sample_ssq', methods=['POST'])
def index():
    data = request.get_json(force=True)
    print(data, flush=True)
    #rint(data['group'], flush=True)
    #print(data['queries'][1]['data'][0][0],data['queries'][1]['data'][0][1], flush=True)
    collection = mongo.db.SenseSquare_Raw
    collection.update_one(data['queries'][0]['data'][0],data['queries'][0]['data'][1], upsert=True)  
    #collection = mongo.db.SenseSquare_Avg
    #collection.update_one(data['queries'][1]['data'][0][0],data['queries'][1]['data'][0][1], upsert=True)
    collection = "SenseSquare_Avg_7D_"+str(data['group'][0])
    #mongo.db[collection].update_one(data['queries'][1]['data'][1][0],data['queries'][1]['data'][1][1], upsert=True)
    #mongo.db[collection].update_one(data['queries'][1]['data'][0][0],data['queries'][1]['data'][0][1], upsert=True)
    mongo.db[collection].update_one(data['queries'][2]['data'][0],data['queries'][2]['data'][1], upsert=True)

    #mongo.db[collection].update_one(data['queries'][2]['data'][0],data['queries'][2]['data'][1], upsert=True)
    return 'Ok'

@main.route('/send_sample_copernicus', methods=['POST'])
def index2():
    data = request.get_json(force=True)
    #print(data, flush=True)
    #print(data['queries']['data'][0][0], flush=True)
    #print(data['queries']['data'][0][1], flush=True)
    collection = mongo.db.Copernicus_Raw
    collection.update_one(data['queries'][0]['data'][0],data['queries'][0]['data'][1], upsert=True)  
    collection = mongo.db.Copernicus_Avg
    collection.update_one(data['queries'][1]['data'][0],data['queries'][1]['data'][1], upsert=True)
    collection = mongo.db.Copernicus_Avg_7D
    collection.update_one(data['queries'][1]['data'][0],data['queries'][1]['data'][1], upsert=True)
    return 'Ok'
@main.route('/send_sample_arpa', methods=['GET'])
def index3():
    day=str(datetime.datetime.today().weekday())
    collection="SenseSquare7D_"+str(day)
    mongo.db.drop_collection(collection)
    return 'Ok'

# @main.route('/docs_delete', methods=['POST'])
# def index():
#     data = request.get_json(force=True)
#     #print(data, flush=True)
#     #print(data['queries']['data'][0][0], flush=True)
#     #print(data['queries']['data'][0][1], flush=True)
#     collection = mongo.db.Arpa_Avg_7D
#   #  collection.remove({"_id.timestamp" $lte Date.now()-7day})
#     collection = mongo.db.Arpa_Avg_7D
#     collection.remove({})
#     collection = mongo.db.Arpa_Avg_7D
#     collection.remove({})
#     return 'Ok'

@main.route('/send_sample_meteo', methods=['POST'])
def index4():
    data = request.get_json(force=True)
    #print(data, flush=True)
    #print(data['queries']['data'][0][0], flush=True)
    #print(data['queries']['data'][0][1], flush=True)
    collection = mongo.db.Meteo_Raw
    collection.update_one(data['queries'][0]['data'][0],data['queries'][0]['data'][1], upsert=True)  
    collection = mongo.db.Meteo_Avg
    collection.update_one(data['queries'][1]['data'][0],data['queries'][1]['data'][1], upsert=True)
    collection = mongo.db.Meteo_Avg_7D
    collection.update_one(data['queries'][1]['data'][0],data['queries'][1]['data'][1], upsert=True)
    return 'Ok'

@main.route('/send_sample_traffico', methods=['POST'])
def index5():
    data = request.get_json(force=True)
    #print(data, flush=True)
    #print(data['queries']['data'][0][0], flush=True)
    #print(data['queries']['data'][0][1], flush=True)
    collection = mongo.db.Traffico_Raw
    collection.update_one(data['queries']['data'][0],data['queries']['data'][1], upsert=True)  
    collection = mongo.db.Traffico_Avg
    collection.update_one(data['queries']['data'][0],data['queries']['data'][1], upsert=True)
    collection = mongo.db.Traffico_Avg_7D
    collection.update_one(data['queries'][1]['data'][0],data['queries'][1]['data'][1], upsert=True)
    return 'Ok'

@main.route('/get_user_info', methods=['GET'])
@jwt_required
def get_user_info():
    data = request.get_data()
    data = int(data)
    data = str(data)
    print(data, flush=True)
    collection = mongo.db.users
    result= collection.find_one({"_id": data})
    if result:
        return jsonify(result), 200
    else:
        return '<h>User not found!</h>'

@main.route('/register', methods=['POST'])
def register():
    ''' register user endpoint '''
    data=request.get_json(force=True)
    print(data, flush=True)
    data = validate_user(request.get_json(force=True))
    if data['ok']:
        data = data['data']
        data['user_info']['password'] = flask_bcrypt.generate_password_hash(data['user_info']['password']).decode('utf8')
        mongo.db.users.insert_one(data)
        return jsonify({'ok': True, 'message': 'User created successfully!'}), 200
    else:
        return jsonify({'ok': False, 'message': 'Bad request parameters: {}'.format(data['message'])}), 400

@main.route('/auth_user', methods=['POST'])
def auth_user():
    ''' auth endpoint '''
    data = request.get_json(force=True)
    #print(data, flush=True)
    print(request.headers, flush=True)
    #if data['ok']
    #data = data['data']
    user = mongo.db.users.find_one({'email': data['email']})
    print(user, flush=True)
    if user and flask_bcrypt.check_password_hash(user['password'], data['password']):
        del user['password']
        access_token = create_access_token(identity=data)
        refresh_token = create_refresh_token(identity=data)
        #user['token'] = access_token
        #user['refresh'] = refresh_token
        resp = jsonify({'login': True, 'data': user})
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        # for group in user['group']:
        #     collection="SenseSquare_Avg_7D_"+group
        #     doc=mongo.db[collection].find_one({"_id" : data['date'] }, { "_id":0  })
            
        # user['avg_dail']=
        print(resp.headers, flush=True)
        return resp, 200
    else:
        return jsonify({'ok': False, 'message': 'invalid username or password'}), 401


@main.route('/auth_sensor', methods=['POST'])
def auth_sensor():
    ''' auth endpoint '''
    data = request.get_json(force=True)
    sensor = mongo.db.Sensors.find_one({'_id': data['_id']})
    #print(sensor, flush=True)
    if sensor and flask_bcrypt.check_password_hash(sensor['key'], data['key']):
        del sensor['key']
        del sensor['_id']
        access_token = create_access_token(identity=data)
        refresh_token = create_refresh_token(identity=data)
        sensor['token'] = access_token
        sensor['refresh'] = refresh_token
        return jsonify({'ok': True, 'data': sensor}), 200
    else:
        return jsonify({'ok': False, 'message': 'invalid username or password'}), 401



@main.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    ''' refresh token endpoint '''
    current_user = get_jwt_identity()
    print(request.headers, flush=True)
    #print(current_user, flush=True)
    
    access_token = create_access_token(identity=current_user)
    
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    return resp, 200


@main.route('/refresh1', methods=['POST'])
@jwt_refresh_token_required
def refresh1():
    ''' refresh token endpoint '''
    current_user = get_jwt_identity()
    ret = {
            'token': create_access_token(identity=current_user)
    }
    return jsonify({'ok': True, 'data': ret}), 200

@flask_jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({
        'ok': False,
        'message': 'Missing Authorization Header'
    }), 401