import flask
import flask_socketio

import functions.winpcapy as winpcapy
import loggers
from exceptions import *

app = flask.Flask("network", static_folder=r'templates\assets', static_url_path='/assets')
app.config['SECRET_KEY'] = 'akey'
socketio = flask_socketio.SocketIO(app)
winp = winpcapy.WinPCap()

ERR_MESSAGE_HTTP_500 = "Unknown Internal Server Error: {}."

logger = loggers.new_logger("api", "WARN")


@socketio.on_error()
def error_handler(e):
    if isinstance(e, MyException):
        logger.error(type(e).__name__ + ":" + e.message)
        socketio.emit('error', {"type": type(e).__name__, "message": e.message})
    else:
        logger.error(type(e).__name__ + ":" + str(e))
        socketio.emit('error', {"type": type(e).__name__, "message": str(e)})


@socketio.on('disconnect')
def remove_thread():
    winp.remove_t(flask.request.sid)


@socketio.on('list_devices_req')
def list_all_devices():
    socketio.emit('list_devices_resp', {"devices": winp.list_all_devices()})


@socketio.on('set_device_req')
def set_device(device_name):
    winp.set_device_t(flask.request.sid, device_name)
    socketio.emit('set_device_resp', device_name)


@socketio.on('set_protos_req')
def set_protos(protos):
    winp.set_protos_t(flask.request.sid, protos)
    socketio.emit('set_protos_resp', ' and '.join(protos))


@socketio.on('run_req')
def run_thread():
    winp.run_t(flask.request.sid, lambda x: socketio.emit("run_resp", x.to_printable_dict()))
    socketio.emit('start_resp')


@socketio.on('stop_req')
def stop_thread():
    winp.stop_t(flask.request.sid)
    socketio.emit('stop_resp')


@app.route('/')
def index():
    return flask.render_template(r"index.html",
                                 device_infos=winp.list_all_devices(),
                                 protocols=["HTTP", "FTP", "TCP", "UDP", "ARP", "RARP", "IP", "ICMP"])


if __name__ == '__main__':
    socketio.run(app)
