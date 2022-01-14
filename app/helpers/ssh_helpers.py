import logging
import paramiko
import subprocess
import yaml, time, json, socket
from helpers.rpi_helpers import get_date_data, last_date_validation, save_time_data

with open('/app/config/config.json') as config_json_file:
    config = json.load(config_json_file)

log = logging.getLogger('rpi')
console = logging.StreamHandler()
log.addHandler(console)
log.setLevel(logging.INFO)

try:
    conf_ssh = config['ssh_server']
except:
    log.info('Ssh server not found in config.json')

if not 'host' in conf_ssh:
    host = "localhost"
else:
    if conf_ssh['host'].strip() == '':
        host = "localhost"
    else:
        host = conf_ssh['host']

if not 'port' in conf_ssh:
    port = 22
else:
    if conf_ssh['port'].strip() == '':
        port = 22
    else:
        port = conf_ssh['port']


try:
    user = conf_ssh['user']
    password = conf_ssh['pass']
except:
    log.info('Missing user or pass in config.json')


def exec_cmd(client, cmd, getlines):
    lines = []
    results = []
    errors = []
    stdin, stdout, stderr = client.exec_command(cmd)
    lines = stdout.readlines()
    errors = stderr.readlines()
    out_ext_status = stdout.channel.recv_exit_status()
    err_ext_status = stderr.channel.recv_exit_status()
    
    if err_ext_status != 0 or out_ext_status != 0:
        log.info(f'Errors: {errors}')
    else:
        log.info(f'Output: {lines}')

    if getlines:
        for line in lines:
            results.append(line.strip('\n'))
        if out_ext_status == 0 and err_ext_status == 0:
            return True, results
        else:
            return False, []
    else:
        if err_ext_status != 0:
            return False
        else:
            return True

def ssh_conn(command,getlines):
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port, user, password)
        if getlines:
            status, data = exec_cmd(client, command, getlines)
            return status, data
        else:
            status= exec_cmd(client, command, getlines)
            return status
        
    except Exception as e:
        log.info(f'Except: {e}')
        if getlines:
            return False, []
        else:
            return False
    finally:
        if client:
            client.close()

def validate_wifi_conn(host="8.8.8.8", port=53, timeout=.25):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error as ex:
        log.info(ex)
        return False

def find_volatile_file():
    process = subprocess.Popen(['find', '/tmp/set_date.txt'],
    stdout=subprocess.PIPE, 
    stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stdout:
        return True
    else:
        return False
    

def create_volatile_file():
    process = subprocess.Popen(['touch', '/tmp/set_date.txt'],
    stdout=subprocess.PIPE, 
    stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if not stderr:
        return True
    else:
        return False

def rasp_start():

    client = None
    ntp_cmd = "sudo timedatectl set-ntp true"
    get_date_cmd = "date '+%Y-%m-%d %H:%M:%S'"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port, user, password)

        conn_status = validate_wifi_conn()
        if conn_status:
            ntp = exec_cmd(client,ntp_cmd, False)
            time.sleep(.5)
            if ntp:
                status, date = exec_cmd(client, get_date_cmd, True)
                if status:
                    save_time_data('',date[0])
                    create_volatile_file()
                    return True
                else:
                    return False
            else:
                return False
        else:
            return True
    except Exception as e:
        log.info(f'RaspStart Except {e}')
        return False
    finally:
        if client:
            client.close()

def set_datetime():

    ntp_cmd = "sudo timedatectl set-ntp true"
    get_date_cmd = "date '+%Y-%m-%d %H:%M:%S'"
    ntp_false_cmd = 'sudo timedatectl set-ntp false'

    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port, user, password)

        conn = validate_wifi_conn()
        file_exists = find_volatile_file()

        if conn and file_exists:
            return False, 'ok'

        if conn and not file_exists:
            exec_cmd(client,ntp_cmd, False)
            time.sleep(.5)
            status, date = exec_cmd(client, get_date_cmd, True)
            if status:
                save_time_data('',date[0])
                create_volatile_file()
                return False, 'ok'

        if file_exists:
            return False, 'ok'
        else:
            new_date = get_date_data()
            valid = last_date_validation(new_date)

            if valid:
                disable_ntp = exec_cmd(client, ntp_false_cmd, False)
                if disable_ntp:
                    set_date_cmd = f"sudo date --set '{new_date}'"
                    set_success = exec_cmd(client, set_date_cmd, False)
                    if set_success:
                        save_time_data('',new_date)
                        create_volatile_file()
                        return True, 'ok'
                    else:
                        return False, 'error set date'
                else:
                    return False, 'error disable ntp'
            else:
                return False, 'error date not valid'
                
    except Exception as e:
        log.info(f'Setdate Except: {e}')
        return False, 'error on exec command'
    finally:
        if client:
            client.close()

def netplan_apply():
    timeout = time.time() + 5
    while timeout > time.time():
        netplan_cmd = "sudo netplan apply"
        ssh_conn(netplan_cmd,False)

def set_static_ip(ip, interface, gateway):
    dns = gateway
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port, user, password)
        
        cmd_nameserver = f"sudo bash -c 'echo nameserver {gateway} > /etc/resolv.conf'"
        nameserv = exec_cmd(client,cmd_nameserver, False)
        if nameserv:
            get_filename = "echo /app/netplan/*.yaml"
            process = subprocess.Popen(get_filename, stdout=subprocess.PIPE,shell=True)
            output, error = process.communicate()
            out = str(output)
            file = out.split('/')
            filename = file[3][0:-3]

            dict_file = {'network': {'ethernets': {f'{interface}': {'dhcp4': False, 'addresses': [f'{ip}/24'], 'gateway4': f'{gateway}', 'nameservers': {'addresses': [f'{dns}']}}}, 'version': 2}}

            with open(f'netplan/{filename}','w') as file:
                documents = yaml.dump(dict_file, file)

            return True 
        else:
            return False
    except Exception as e:
        log.info(f'StaticIp Except: {e}')
        return False, 'error on exec command'
    finally:
        if client:
            client.close()

def valid_os(msg):
    linux = False
    try:
        status, output = ssh_conn('uname', True)
        if status:
            for i in range(len(output)):
                if output[i].lower().strip().__contains__('linux'):
                    linux = True
                    break
    except Exception as e:
        if msg:
            log.info('This function only works in linux')
    return linux