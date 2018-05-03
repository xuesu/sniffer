import flask
import flask_socketio

import functions.winpcapy as winpcapy
import loggers
import packet
import utils
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
    proto_filter_str = winp.set_protos_t(flask.request.sid, protos)
    socketio.emit('set_protos_resp', proto_filter_str)


@socketio.on('run_req')
def run_thread():
    winp.run_t(flask.request.sid, lambda x: socketio.emit("run_resp", utils.packet2printable_dict(x)))
    socketio.emit('start_resp')


@socketio.on('stop_req')
def stop_thread():
    winp.stop_t(flask.request.sid)
    socketio.emit('stop_resp')


@socketio.on('add_addr_filter_req')
def add_addr_filter(from_s, type_s, addr):
    addr_filters_strs = winp.add_addr_filter_t(flask.request.sid, from_s.strip(), type_s.strip(), addr.strip())
    socketio.emit('add_addr_filter_resp', addr_filters_strs)


@socketio.on('remove_addr_filter_req')
def remove_addr_filter(ind):
    addr_filters_strs = winp.remove_addr_filter_t(flask.request.sid, ind)
    socketio.emit('remove_addr_filter_resp', addr_filters_strs)


@app.route('/')
def index():
    return flask.render_template(r"index.html",
                                 device_infos=winp.list_all_devices(),
                                 protocols=[proto.name for proto in packet.Packet.PROTOCOL][1:])


if __name__ == '__main__':
    socketio.run(app)
