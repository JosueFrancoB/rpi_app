import os
import logging
import threading
import subprocess
from flask_cors import CORS
from flask_redoc import Redoc
from routes.rpi_routes import rpi
from flask import Flask, request, jsonify
from helpers.ssh_helpers import rasp_start, valid_os
from helpers.config_helpers import *

app = Flask(__name__)
CORS(app)
app.register_blueprint(rpi)
redoc = Redoc(app, 'doc.yml')

log = logging.getLogger('rpi')
console = logging.StreamHandler()
log.addHandler(console)
log.setLevel(logging.INFO)

try:
    app_port = config_h['app']['port']
except:
    app_port = 5000

# 404 error handler
@app.errorhandler(404)
def notFound(error=None):

    msg = jsonify({
        'msg': 'Resource not found ' + request.url,
        'msg_es': 'Recurso no encontrado ' + request.url,
        'status': 404,
    }), 404
    return msg


def running():
    status = False
    if datetime_enabled and valid_os(True):
        while not status:
            status = rasp_start()
    app.run(debug = False, host="0.0.0.0", port = app_port)

def hostapd():
    if hostapd_enabled and valid_os(True):
        command = "/bin/wlanstart.sh"
        process = subprocess.Popen(command, stdout=subprocess.PIPE,shell=True, preexec_fn=os.setsid)
        output, error = process.communicate()
        log.info(f'Output: {output}')
        log.info(f'Error: {error}')

app_thread = threading.Thread(target=running)
hostapd_thread = threading.Thread(target=hostapd)

if __name__ == '__main__':
    hostapd_thread.start()
    app_thread.start()
    hostapd_thread.join()
    app_thread.join()