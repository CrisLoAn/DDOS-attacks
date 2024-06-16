#!/usr/bin/python3

import csv
import threading
import time
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from collections import deque

# Predictor variables
alpha = 0.5
T_n = 256
Tau_n = 256
previous_frame_size = 256  # Use snake_case for variable naming

fig, ax = plt.subplots()
x, y = [], []

# Config variables
registros_file = '/usr/local/src/DDOs-folder/config/registros.csv'  # Replace with the actual path to your CSV file
current_frame = []
predictions = deque(maxlen=300)  # Keeping a history of predictions
packet_counts = deque(maxlen=300)  # Maintain a 60-second history of data
stop_thread = False

def load_requests(file):
    global current_frame  # Only modify current_frame within the function
    try:
        with open(file, mode='r', newline='') as csv_file:
            csv_reader = csv.reader(csv_file)
            current_frame = [row for row in csv_reader]
    except FileNotFoundError:
        print(f"Error: The file '{file}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

def get_next_prediction(tn, tau_n):
    global alpha, current_frame, previous_frame_size
    tau_n1 = alpha * tn + (1 - alpha) * tau_n
    update_predictor_variables(len(current_frame), int(tau_n1))
    previous_frame_size = tn
    return int(tau_n1)

def update_predictor_variables(current_load, prediction):
    global Tau_n, T_n
    T_n = current_load
    Tau_n = prediction

def predict_request():
    global T_n, Tau_n
    Tau_n1 = get_next_prediction(T_n, Tau_n)
    print(f'Predictor -> received:[{T_n}], predicted:[{Tau_n1}], previous:[{Tau_n}]')
    predictions.append(Tau_n1)

def prediction_thread():
    global stop_thread
    # We run for the first time with the default values
    predict_request()

    while not stop_thread:
        load_requests(registros_file)
        predict_request()
        time.sleep(1)  # Adjust the sleep time as needed

def update(frame):
    global previous_frame_size, x, y
    if len(predictions) > 0:
        previous_frame_size = predictions[-1]  # Update with the latest prediction
    x.append(time.time())  # Assuming you want the x-axis to represent time
    y.append(previous_frame_size)  # Assuming 'previous_frame_size' is a variable that updates
    ax.clear()
    ax.plot(x, y)
    ax.set_xlabel('Time')
    ax.set_ylabel('Frame Width')
    ax.set_title('Real-Time Frame Width Viewer')

def graficar():
    # Animation configuration
    ani = animation.FuncAnimation(fig, update, interval=500)
    plt.show()

# Create and start the prediction thread
thread = threading.Thread(target=prediction_thread)
thread.start()

# Main program continues running and can perform other tasks
try:
    # Call the graficar function to display the graph
    graficar()
except KeyboardInterrupt:
    # Stop the prediction thread gracefully on interrupt
    stop_thread = True
    thread.join()
    print("Prediction thread stopped.")
