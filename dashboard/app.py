# import sys
# import os
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# from flask import Flask, render_template
# from analyzer.topology_builder import build_topology
# from visualizer.graph_visualizer import visualize_topology

# app = Flask(__name__)

# @app.route('/')
# def index():
#     devices = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
#     links = [('192.168.1.1', '192.168.1.2'), ('192.168.1.2', '192.168.1.3')]
#     graph = build_topology(devices, links)
#     visualize_topology(graph)
#     return render_template('index.html')

# if __name__ == '__main__':
#     app.run(debug=True)
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from visualizer.graph_visualizer import get_graph_data
import threading
import time
from analyzer.topology_builder import build_topology


app = Flask(__name__)
socketio = SocketIO(app)

current_topology = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/topology_data')
def topology_data():
    graph = build_topology()
    data = get_graph_data(graph)
    return jsonify(data)

def refresh_topology():
    global current_topology
    while True:
        print("Refreshing topology...")
        current_topology = build_topology()  # use build_topology instead
        data = get_graph_data(current_topology)
        socketio.emit('update_topology', data)
        time.sleep(10)  # refresh every 10 seconds


if __name__ == '__main__':
    topology_thread = threading.Thread(target=refresh_topology)
    topology_thread.daemon = True
    topology_thread.start()
    socketio.run(app, debug=True)
