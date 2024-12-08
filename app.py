import sys

import eventlet
eventlet.monkey_patch()

import threading
import webbrowser
from flask import Flask, render_template, jsonify, request

from db import SessionLocal
from alertManager import cpe_extractor
from core import main
from models import Server
import logging
from socketio_manager import socketio


app = Flask(__name__)

event_queue = []
event_updates = []
app.config['SECRET_KEY'] = 'kali'
socketio.init_app(app)
session = SessionLocal()



log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


@app.route('/')
def index():
    servers = session.query(Server).all()
    return render_template('index.html', servers=servers)


@app.route('/server/<ip>:<port>')
def server_details(ip, port):
    server = f"{ip}:{port}"
    return render_template('server_details.html', server=server)


@app.route('/api/server_statuses')
def api_server_statuses():
    servers = {
        f"{server.ip}:{server.port}": {
            "overall_status": server.overall_status,
            "attacks": {
                attack.id: {
                    "attack_name": attack.attack_name,
                    "tool": attack.tool,
                    "vulnerable": attack.vulnerable,
                    "log_content": attack.log_content,
                    "timestamp": attack.timestamp.isoformat(),
                }
                for attack in server.attacks
            }
        }
        for server in session.query(Server).filter(Server.port != '').all()
    }
    return jsonify(servers)


@app.route('/api/server_details/<ip>:<port>')
def api_server_details(ip, port):
    server_obj = session.query(Server).filter_by(ip=ip, port=port).first()
    if server_obj:
        return jsonify({
            "ip": server_obj.ip,
            "port": server_obj.port,
            "overall_status": server_obj.overall_status,
            "attacks": {
                attack.id: {
                    "attack_name": attack.attack_name,
                    "tool": attack.tool,
                    "vulnerable": attack.vulnerable,
                    "log_content": attack.log_content,
                    "timestamp": attack.timestamp.isoformat(),
                }
                for attack in server_obj.attacks
            }
        })
    return jsonify({}), 404

@app.route('/charts/<server_key>')
def charts_page(server_key):
    return render_template('charts.html', server_key=server_key)



@app.route('/api/openvas_alert', methods=['GET'])
def openvas_alert():
    cpe_extractor()
    return jsonify({"message": "CPEs updated successfully!"}), 200


def open_browser():
    """
    Open the web browser to the Flask application's root URL.
    """
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == '__main__':
    cpe_extractor()
    threading.Thread(target=main, args=(sys.argv[1:],), daemon=True).start()
    threading.Timer(1, open_browser).start()
    socketio.run(app, debug=False)
