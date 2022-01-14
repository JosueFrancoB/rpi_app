import re, logging
from threading import Thread
from helpers.config_helpers import *
from middlewares.app_middlewares import *
from flask import Blueprint, jsonify, Response
from helpers.ssh_helpers import ssh_conn, set_datetime, set_static_ip, netplan_apply, validate_wifi_conn
from helpers.rpi_helpers import get_wifi_data, wifi_request, change_wifi_data, get_timezone, get_command, save_time_data, get_ip_data, get_about, valid_print_ipaddr



log = logging.getLogger('rpi')
console = logging.StreamHandler()
log.addHandler(console)
log.setLevel(logging.INFO)


rpi = Blueprint('rpi', __name__)

#Reboot raspberry
@rpi.route('/reboot',methods=['POST'])
@validate_os
@validate_jwt
@validate_app_functions
def rpi_reboot():
    if reboot_enabled:
        status = ssh_conn('sudo reboot now', False)
        if status:
            return jsonify({
                'msg': 'Raspberry is restarting',
                'msg_es': 'El raspberry se está reiniciando'
            }), 200
        else:
            return jsonify({
                'error': 'An error has ocurred on reboot',
                'error_es': 'Ha ocurrido un error al reiniciar'
            }), 500
    else:
        return jsonify({
            'msg': 'Reboot function is disabled',
            'msg_es': 'La funcion de reiniciar esta desactivada'
        }), 200

#Shutdown raspberry
@rpi.route('/shutdown',methods=['POST'])
@validate_os
@validate_jwt
@validate_app_functions
def rpi_shutdown():
    if shutdown_enabled:
        status = ssh_conn('sudo shutdown now', False)
        if status:
            return jsonify({
                'msg': 'Raspberry was shutdown successfully',
                'msg_es': 'El raspberry se apagó correctamente'
            }), 200
        else:
            return jsonify({
                'error': 'An error has ocurred on shutdown',
                'error_es': 'Ha ocurrido un error al apagar'
            }), 500
    else:
        return jsonify({
            'msg': 'Shutdown function is disabled',
            'msg_es': 'La funcion de apagar esta desactivada'
        }), 200

#Change datetime raspberry
@rpi.route('/datetime',methods=['PATCH'])
@validate_os
@validate_jwt
@validate_app_functions
@validate_datetime
def rpi_datetime():
    if datetime_enabled:
        status, msg = set_datetime()
        if not status and msg == 'ok':
            return jsonify({
                'msg': 'Date and time are already up to date',
                'msg_es': 'La fecha y la hora ya están actualizadas'
            }), 200
        
        if not status and msg != 'ok':
            if msg.__contains__('set') :
                return jsonify({
                    'error': 'An error ocurred on set date',
                    'error_es': 'Ha ocurrido un error al asignar la fecha'
                }), 500
            elif msg.__contains__('ntp'):
                return jsonify({
                    'error': 'An error ocurred on disable ntp',
                    'error_es': 'Ha ocurrido un error al desactivar el ntp'
                }), 500
            elif msg.__contains__('exec'):
                return jsonify({
                    'error': 'An error ocurred',
                    'error_es': 'Ha ocurrido un error'
                }), 500
            elif msg.__contains__('valid'):
                return jsonify({
                    'error': 'Date and time invalid',
                    'error_es': 'La fecha y la hora son inválidas'
                }), 400
        
        if status and msg == 'ok':
            return jsonify({
                'msg': 'Datetime was updated successfully',
                'msg_es': 'Fecha y hora actualizados correctamente'
            }), 200
    else:
        return jsonify(config_resp['datetime']), 200

    
#Change name and password wifi hostapd
@rpi.route('/wifi',methods=['PATCH'])
@validate_os
@validate_jwt
@validate_app_functions
@validate_wifi_data
def rpi_wifi():
    if hostapd_enabled: 
        data = wifi_request()
        
        status = change_wifi_data(data)
        if status:
            return jsonify({
                'msg': 'Wifi data was update successfully',
                'msg_es': 'Los datos del internet se actualizaron correctamente'
            }), 200
        else:
            return jsonify({
                'error': 'An error has ocurred with wifi_config.json',
                'error_es': 'Ha ocurrido un error con wifi_config.json'
            }), 500
    else:
        return jsonify(config_resp['hostapd']), 200


#Get name and password wifi hostapd
@rpi.route('/wifi',methods=['GET'])
@validate_os
@validate_jwt
@validate_app_functions
def rpi_get_wifi():
    if hostapd_enabled:
        data = get_wifi_data()
        if data != 'error':
            return jsonify(data), 200
        else:
            return jsonify({
                'error': 'An error has ocurred with wifi_config.json',
                'error_es': 'Ha ocurrido un error con wifi_config.json'
            }), 500
    else:
        return jsonify(config_resp['hostapd']), 200



#Get my timezone with geolocation
@rpi.route('/my-timezone',methods=['GET'])
@validate_os
@validate_jwt
@validate_app_functions
def get_my_time_zone():
    if datetime_enabled:
        status, zone = ssh_conn('curl -s https://ipapi.co/timezone;echo', True)
        if status and len(zone)>0:
            if re.fullmatch(r'^(([a-zA-Z_])+(/){0,1})+', zone[0]):
                return jsonify({
                    "timezone": zone[0]
                }), 200
            else:
                return jsonify({
                'error': 'An error has ocurred with wifi connection',
                'error_es': 'Ha ocurrido un error con la conexion a internet'
                }), 502
        else:
            return jsonify({
                'error': 'An error has ocurred on get timezone',
                'error_es': 'Ha ocurrido un error al obtener la zona horaria'
            }), 500
    else:
        return jsonify(config_resp['datetime']), 200



#Get available America time zones
@rpi.route('/timezone',methods=['GET'])
@validate_os
@validate_jwt
@validate_app_functions
def get_all_time_zones():
    if datetime_enabled:
        status, zones = ssh_conn('timedatectl list-timezones | grep America', True)
        if status:
            return jsonify({
                "zones": zones
            }), 200
        else:
            return jsonify({
                'error': 'An error has on get timezones',
                'error_es': 'Ha ocurrido un error al obtener zonas horarias'
            }), 500
    else:
        return jsonify(config_resp['datetime']), 200


#Set an specific time zone
@rpi.route('/timezone',methods=['POST'])
@validate_os
@validate_jwt
@validate_app_functions
@validate_timezone
def set_time_zone():
    if datetime_enabled:
        timezone = get_timezone()
        status = ssh_conn(f'sudo timedatectl set-timezone {timezone}', False)
        if status:
            save_status = save_time_data(timezone,'')
            if not save_status:
                    return jsonify({
                        'error': 'An error has ocurred with date_config.json',
                        'error_es': 'Ha ocurrido un error con date_config.json'
                    }), 500
            else:
                return jsonify({
                    'msg': 'Timezone was updated successfully',
                    'msg_es': 'La zona horaria se actualizó correctamente'
                }), 200
        else:
            return jsonify({
                'error': 'An error has ocurred on set time zone',
                'error_es': 'Ha ocurrido un error al cambiar la zona horaria'
            }), 500
    else:
        return jsonify(config_resp['datetime']), 200


#Send command to execute on raspberry
@rpi.route('/command',methods=['POST'])
@validate_os
@validate_jwt
@validate_cmd
def rpi_command():
    cmd, getoutput = get_command()
    if getoutput:
        status, output = ssh_conn(cmd, getoutput)
    else:
        status = ssh_conn(cmd, getoutput)

    if status and getoutput:
        return jsonify({
            "cmd_ouput": output
        }), 200
    elif status and not getoutput:
        return jsonify({
            "msg": "Command was execute successfully",
            "msg_es": "El comando se ejecuto exitosamenete",
        }), 200
    else:
        return jsonify({
            'error': 'An error has ocurred on command execution',
            'error_es': 'Ha ocurrido un error en la ejecución del comando'
        }), 500

#Get mac address 
@rpi.route('/macaddr',methods=['GET'])
@validate_os
@validate_jwt
def rpi_mac():

    get_ip = "hostname -I | awk '{print $1}'"
    status, output = ssh_conn(get_ip, True)
    if status and len(output) > 0:
        dev_ip = output[0]
        log.info(f'-------- La ip de para la mac ------- {dev_ip}')
    else:
        return jsonify({
            'error': 'An error has ocurred',
            'error_es': 'Ha ocurrido un error'
        }), 500
    
    dev_ip = str(dev_ip).replace('.', '[.]')
    cmd_mac = "ifconfig | grep "+ dev_ip + " -A 5 | grep 'ether' | awk '{print $2}'"
    log.info(f'-------- El comando para la mac ------- {cmd_mac}')
    status, output = ssh_conn(cmd_mac, True)
    
    if status and len(output) > 0:
        return jsonify({
            "mac_addr": output[0]
        }), 200
    else:
        return jsonify({
            'error': 'An error has ocurred',
            'error_es': 'Ha ocurrido un error'
        }), 500


#Scan mac by ip addr
@rpi.route('/scan-mac/<ipaddr>',methods=['GET'])
@validate_os
@validate_jwt
def scan_macaddr(ipaddr):
    mac = None
    errors, errors_es = valid_print_ipaddr(ipaddr)
    cmd_scan = 'arp -D ' + ipaddr
    status, output = ssh_conn(cmd_scan, True)
    if len(output) > 0:
        mac = ' '.join(str(output[1]).split()).split()[2]
    
    if len(errors) > 0 or not status:
        return jsonify({
            "msg": errors,
            "msg_es": errors_es
        }), 500
    else:
        return jsonify({
            "mac_addr": mac
        }), 200

#Set raspberry static ip
@rpi.route('/static-ip',methods=['POST'])
@validate_os
@validate_jwt
@validate_static_ip
def set_ip():
    ip, interface, gateway = get_ip_data()
    status = set_static_ip(ip, interface, gateway)
    
    if status:
        thread = Thread(target=netplan_apply)
        thread.start()
        return jsonify({
            "msg": "File with static ip was update successfully",
            "msg_es": "El archivo con la ip estatica se actualizó correctamente"
        }), 200
    else:
        return jsonify({
            'msg': 'An error was ocurred',
            'msg_es': 'Ha ocurrido un error'
        }), 500

#Get about from project
@rpi.route('/about',methods=['GET'])
def about():
    app, version = get_about()
    
    return jsonify({
        "name": app,
        "version": version
    }), 200

#Check wifi connection
@rpi.route('/wifi-conn', methods=['GET'])
@validate_app_functions
def wifi_connection():
    if check_wifi_enabled:
        status  = validate_wifi_conn()

        if status:
            return jsonify({
                "connection": True,
                "msg": "Has internet connection",
                "msg_es": "Tienes conexión a internet"
            }), 200
        else:
            return jsonify({
                "connection": False,
                "msg": "No internet connection",
                "msg_es": "No tienes conexión a internet"
            }), 200
    else:
        return jsonify({
            'msg': 'Check wifi funtion is disabled',
            'msg_es': 'La funcion de check_wifi esta desactivada'
        }), 200
