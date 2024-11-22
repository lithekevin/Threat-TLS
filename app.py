from flask import Flask, render_template, jsonify, redirect, url_for, Response
import threading
import os
import time
from main import main
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)

# Global dictionary to store server statuses
server_statuses = {}
logs_path = './Logs/'

# Event queue to notify clients
event_queue = []


# Create an instance of LogHandler

def check_vulnerability(log_content):
    # Simple check: if certain keywords are found in the log, mark as vulnerable
    vulnerable_keywords = ['VULNERABLE (NOT ok)', 'VULNERABLE', 'probably', 'leak']
    for keyword in vulnerable_keywords:
        if keyword in log_content:
            return True
    return False


class LogHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.log'):
            self.process_log(event.src_path)
            self.notify_clients()

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('.log'):
            self.process_log(event.src_path)
            self.notify_clients()

    def process_log(self, filepath):
        ip_port = os.path.basename(os.path.dirname(filepath))
        attack = os.path.basename(filepath).replace('.log', '')
        with open(filepath, 'r') as f:
            content = f.read()
            # Check for indications of vulnerabilities
            vulnerable = check_vulnerability(content)
            # Update the server status
            if ip_port not in server_statuses:
                server_statuses[ip_port] = {'attacks': {}, 'overall_status': 'Secure'}
            server_statuses[ip_port]['attacks'][attack] = {'vulnerable': vulnerable, 'log_content': content}
            # Update overall status
            if vulnerable:
                server_statuses[ip_port]['overall_status'] = 'Vulnerable'

    def notify_clients(self):
        # Append a new event to the queue that will notify clients of changes
        event_queue.append('data: update\n\n')


log_handler = LogHandler()


def process_existing_logs():
    for root, _, files in os.walk(logs_path):
        for file in files:
            if file.endswith('.log'):
                filepath = os.path.join(root, file)
                log_handler.process_log(filepath)


def start_log_observer():
    event_handler = log_handler
    observer = Observer()
    observer.schedule(event_handler, logs_path, recursive=True)

    # Process existing logs before starting the observer
    process_existing_logs()

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


@app.route('/')
def index():
    return render_template('index.html', server_statuses=server_statuses)


@app.route('/server/<ip_port>')
def server_details(ip_port):
    if ip_port in server_statuses:
        return render_template('server_details.html', server=ip_port, details=server_statuses[ip_port])
    return redirect(url_for('index'))


@app.route('/api/server_statuses')
def api_server_statuses():
    return jsonify(server_statuses)


@app.route('/api/server_details/<ip_port>')
def api_server_details(ip_port):
    if ip_port in server_statuses:
        return jsonify(server_statuses[ip_port])
    return jsonify({})


@app.route('/events')
def events():
    def generate():
        while True:
            if event_queue:
                yield event_queue.pop(0)
            time.sleep(1)

    return Response(generate(), content_type='text/event-stream')


if __name__ == '__main__':
    threading.Thread(target=main, daemon=True).start()
    threading.Thread(target=start_log_observer, daemon=True).start()
    app.run(debug=False)
