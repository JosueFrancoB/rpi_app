import re, json, yaml
from flask import request
from pathlib import Path
from datetime import datetime

def get_wifi_data():
    path = Path(__file__).parent / "../config/wifi_config.json"
    try:
        f = open(path,)
    except:
        return 'error'

    json_data = json.load(f)
    name = json_data['ssid']
    password = json_data['wpa_passphrase']
    f.close()
    return {'name': name, 'password': password}
    

def wifi_request():
    if 'name' in request.json and 'password' in request.json:
        return {'name': request.json['name'].strip(),
        'password': request.json['password'].strip()}
    if 'name' in request.json and not 'password' in request.json:
        return {'name': request.json['name'].strip()}
    if 'password' in request.json and not 'name' in request.json:
        return {'password': request.json['password'].strip()}

def get_date_data():
    if 'date_time' in request.json:
        date = request.json['date_time']
        return date

def get_command():
    if 'command' in request.json:
        cmd = request.json['command']
        
    if 'getoutput' in request.json:
        getoutput = request.json['getoutput']
        if getoutput.lower() == "y":
            getoutput = True
        elif getoutput.lower() == "n":
            getoutput = False
    else:
        getoutput = False
    
    return cmd, getoutput

def get_ip_data():
    if 'static_ip' in request.json:
        ip = request.json['static_ip']

    if 'gateway' in request.json:
        router = request.json['gateway']

    if 'interface' in request.json:
        interface = request.json['interface']

    return ip, interface, router

def get_about():
    with open('doc.yml') as doc:
        documentation = yaml.load(doc, Loader=yaml.FullLoader)
    
    name = documentation['info']['title']
    version = documentation['info']['version']

    return name, version

def change_wifi_data(data):
    path = Path(__file__).parent / "../config/wifi_config.json"
    try:
        f = open(path,)
    except:
        return False
    json_data = json.load(f)
    
    if 'name' in data:
        ssid = data['name']
    else:
        ssid = json_data['ssid']

    if 'password' in data:
        password = data['password']
    else:
        password = json_data['wpa_passphrase']
    
    json_data['ssid'] = ssid
    json_data['wpa_passphrase'] = password

    try:
        with open(path, 'w') as outfile:
            json.dump(json_data, outfile)
    except:
        return False
    f.close()
    return True

    
def save_time_data(timezone,last_date):
    path = Path(__file__).parent / "../config/config.json"
    try:
        f = open(path,)
    except:
        return False
    json_data = json.load(f)
    if timezone != '':
        json_data['date_time']['time_zone'] = timezone 
    if last_date != '':
        json_data['date_time']['last_date'] = last_date
    try:
        with open(path, 'w') as outfile:
            json.dump(json_data, outfile)
    except:
        return False
    f.close()
    return True

def get_timezone():
    if 'time_zone' in request.json:
        zone = request.json['time_zone']
        return zone

def last_date_validation(date):
    date  = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")

    with open('/app/config/config.json') as config_json_file:
        config = json.load(config_json_file)
    
    last_date = config['date_time']['last_date']
    last_date = datetime.strptime(last_date, "%Y-%m-%d %H:%M:%S")

    if date < last_date:
        return False
    else:
        return True


def valid_print_ipaddr(ipaddr):
    errors = []
    errors_es = []
    if not re.fullmatch(r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b', ipaddr):
        errors.append('Ip address format not valid')
        errors_es.append('El formato de la ip no es valido')
    return errors, errors_es