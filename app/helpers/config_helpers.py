import json
import logging
from functools import wraps
from flask import jsonify
from helpers.ssh_helpers import valid_os

log = logging.getLogger('ntfy')
console = logging.StreamHandler()
log.addHandler(console)
log.setLevel(logging.INFO)

with open('/app/config/config.json') as config_json_file:
    config_h = json.load(config_json_file)

hostapd_enabled = False
datetime_enabled = False
shutdown_enabled = False
reboot_enabled = False
check_wifi_enabled = False

try:
    conf_services = config_h['app_functions']
except:
    conf_services = None
    log.info('No app_functions in config.json')

if conf_services:
    if 'hostapd' in conf_services:
        hostapd_enabled = conf_services['hostapd']

    if 'datetime' in conf_services:
        datetime_enabled = conf_services['datetime']

    if 'shutdown' in conf_services:
        shutdown_enabled = conf_services['shutdown']

    if 'reboot' in conf_services:
        reboot_enabled = conf_services['reboot']

    if 'check_wifi' in conf_services:
        check_wifi_enabled = conf_services['check_wifi']


config_resp = {
    'datetime':{
        'msg':'Date and time funtions are disabled',
        'msg_es': 'Las funciones de fecha y hora estan desactivadas'
    },
    'hostapd': {
        'msg': 'Access point is disabled',
        'msg_es': 'El punto de acceso esta desactivado'
    }
}
    


linux_os = valid_os(False)
def validate_os(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not linux_os:
            return jsonify({
                'msg': 'This route only can run on linux',
                'msg_es': 'Esta ruta solo puede correr en linux'
            }), 400
        return f(*args, **kwargs)
    return decorated