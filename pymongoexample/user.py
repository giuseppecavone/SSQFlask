
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from jsonschema.exceptions import SchemaError

user_schema = {
    "type": "object",
    "properties": {
    "_id" : {
        "type": "string"
    },
    "user_info" : { 
        "type": "object",
        "properties": {
        "admin" : {
            "type": "boolean"
        },
        "apikey" : {
            "type": "string"
        },
        "areas" : 
            {
                "type": "array",
                "items": {
                    "cap" :{
                        "type": "string"
                }, 
                    "zona" : {
                        "type": "string"
                } 

                },
                "minItems": 0,
                "uniqueItems": True
            }, 
          
        "types" : {
            "type":"string"
        },
        "password":{
            "type":"string",
            "minLength": 5
        },
        "email":{
            "type": "string",
            "format": "email"
        }
    
    },
    "required": ["email", "password"],
    "additionalProperties": False
    
    }
    }  
}

def validate_user(data):
    try:
        validate(data, user_schema)
    except ValidationError as e:
        return {'ok': False, 'message': e}
    except SchemaError as e:
        return {'ok': False, 'message': e}
    return {'ok': True, 'data': data}

