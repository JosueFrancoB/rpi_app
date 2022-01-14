import os
import re
import json
import logging
import requests
from functools import wraps
from flask import request, jsonify

log = logging.getLogger('rpi')

def validate_wifi_data(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.json:
            return jsonify({
                'error': 'No data was provided',
                'error_es': 'No se recibieron datos'
            }), 400

        if 'name' in request.json:
            name = request.json['name'].strip()
            if len(name)< 5 or len(name) > 32:
                return jsonify({
                    'error': 'Name is not valid min length is 5 characters and max length is 32 characters',
                    'error_es': 'El nombre no es válido y la longitud minima es de 5 caracteres la longitud máxima es de 32 caracteres'
                }), 400
            if not re.fullmatch(r'^[\w]{5,32}', name):
                return jsonify({
                    'error': 'Some characters from name are not valid',
                    'error_es': 'Algunos caracteres del nombre no son válidos'
                }), 400

        if 'password' in request.json:
            password = request.json['password'].strip()
            if len(password)< 8 or len(password) > 63:
                return jsonify({
                    'error': 'Password is not valid min length is 8 characters and max length is 63 characters',
                    'error_es': 'La contraseña no es válida y la longitud minima es de 8 caracteres y la máxima es de 63 caracteres'
                }), 400

            if not re.fullmatch(r'^[A-Za-z0-9@#$%^&+=\-_\.]{8,63}', password):
                return jsonify({
                    'error': 'Some characters from password are not valid',
                    'error_es': 'Algunos caracteres de la contraseña no son válidos'
                }), 400

        if not 'name' in request.json and not 'password' in request.json:
            return jsonify({
                'error': 'No name or password fields was provided',
                'error_es': 'No se recibieron los campos nombre o contraseña'
            }), 400
        return f(*args, **kwargs)
    return decorated

def validate_datetime(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.json:
            return jsonify({
                'error': 'No data was provided',
                'error_es': 'No se recibieron datos'
            }), 400
        
        if 'date_time' in request.json:
            date = request.json['date_time']
            if len(date) != 19:
                return jsonify({
                    'error': 'Datetime format length invalid, YYYY-MM-DD HH:II:SS',
                    'error_es': 'La longitud del formato de datetime no es válido, YYYY-MM-DD HH:II:SS'
                }), 400 
            if date[4] != '-' or  date[7] != '-' or date[13] != ':'or date[16] != ':':
                return jsonify({
                    'error': 'Datetime format is invalid,YYYY-MM-DD HH:II:SS',
                    'error_es': 'El formato de la fecha y hora es inválido, YYYY-MM-DD HH:II:SS'
                }), 400
        else:
            return jsonify({
                'error': 'No date_time field was provided',
                'error_es': 'No se recibio el campo date_time'
            }), 400
        return f(*args, **kwargs)
    return decorated

def validate_timezone(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.json:
            return jsonify({
                'error': 'No data was provided',
                'error_es': 'No se recibieron datos'
            }), 400
        
        if 'time_zone' in request.json:
            zone = request.json['time_zone'].strip()
            if not re.fullmatch(r'^(([a-zA-Z_])+(/){0,1})+', zone):
                return jsonify({
                    'error': 'Time_zone format is invalid, example: America/Mexico_City',
                    'error_es': 'El formato de la zona horaria no es válido, ejemplo: America/Mexico_City'
                }), 400
            if zone[-1] == '/':
                return jsonify({
                    'error': 'Time_zone format is invalid, example: America/Mexico_City',
                    'error_es': 'El formato de la zona horaria no es válido, ejemplo: America/Mexico_City'
                }), 400
        else:
            return jsonify({
                'error': 'No time_zone field was provided',
                'error_es': 'No se recibio el campo time_zone'
            }), 400

        return f(*args, **kwargs)
    return decorated

def validate_cmd(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.json:
            return jsonify({
                'error': 'No data was provided',
                'error_es': 'No se recibieron datos'
            }), 400
        if 'command' in request.json:
            cmd = request.json['command'].strip()

            if cmd.__contains__('sudo'):
                return jsonify({
                    'error': 'Command is invalid',
                    'error_es': 'El comando no es valido'
                }), 400
        else:
            return jsonify({
                'error': 'No command field was provided',
                'error_es': 'No se recibio el campo command'
            }), 400

        if 'getoutput' in request.json:
            getoutput = request.json['getoutput']
            if getoutput.lower() != "y" and getoutput.lower() != "n":
                return jsonify({
                'error': 'getoutput field must be Y or N',
                'error_es': 'El campo getoutput debe de ser Y o N'
            }), 400

        return f(*args, **kwargs)
    return decorated

def validate_static_ip(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.json:
            return jsonify({
                'error': 'No data was provided',
                'error_es': 'No se recibieron datos'
            }), 400

        if 'static_ip' in request.json:
            static_ip = request.json['static_ip']
            if not re.fullmatch(r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b', static_ip):
                return jsonify({
                    'error': 'Ip format is invalid',
                    'error_es': 'El formato de la ip no es valido'
                }), 400
        else:
            return jsonify({
                'error': 'No static_ip field was provided',
                'error_es': 'No se recibio el campo static_ip'
            }), 400
        
        if 'interface' in request.json:
            interface = request.json['interface'].strip()
            if interface != 'eth0' and interface != 'wlan0':
                return jsonify({
                    'error': 'Interface is invalid',
                    'error_es': 'La interfaz no es valida'
                }), 400
        else:
            return jsonify({
                'error': 'No interface field was provided',
                'error_es': 'No se recibio el campo interface'
            }), 400

        if 'gateway' in request.json:
            gateway = request.json['gateway']
            if not re.fullmatch(r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b', gateway):
                return jsonify({
                    'error': 'Gateway format is invalid',
                    'error_es': 'El formato de la puerta de enlace no es valido'
                }), 400
        else:
            return jsonify({
                'error': 'No gateway field was provided',
                'error_es': 'No se recibio el campo gateway'
            }), 400
        return f(*args, **kwargs)
    return decorated

def validate_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        with open('/app/config/config.json') as config_json_file:
            config = json.load(config_json_file)
        try:
            auth_host = config["security"]["jwt_api_host"]
            auth_port = config["security"]["jwt_api_port"]
            auth_endpoint = config["security"]["jwt_api_endpoint"]
        except:
            auth_host = ''
            auth_port = ''
            auth_endpoint = ''
            log.info('security not in config.json, auth validations are disabled')

        if auth_host != '' and auth_port != '' and auth_endpoint != '':
            token = None
            if 'x-token' in request.headers:
                token = request.headers['x-token']
            
            if not token:
                return jsonify({
                    'msg': 'x-token is required',
                    'msg_es': 'x-token es obligatorio'
                }), 401
        
            try:
                r = requests.get(f"http://{auth_host}:{auth_port}{auth_endpoint}", headers={"x-token":token})
            except Exception as e:
                return jsonify({
                    'msg': 'Error validating token',
                    'msg_es': 'Error validando token'
                }), 401

            status = r.status_code

            if status != 200:
                return jsonify({
                    'msg': 'x-token is invalid',
                    'msg_es': 'x-token es invalido'
                }), 401

        return f(*args, **kwargs)
    return decorated


def validate_app_functions(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        with open('/app/config/config.json') as config_json_file:
            config = json.load(config_json_file)
        try:
            conf_services = config['app_functions']
        except:
            return jsonify({
                'msg':'Field app_functions required in config.json',
                'msg_es':'El campo app_functions se requiere en config.json'
            }), 400
        return f(*args, **kwargs)
    return decorated