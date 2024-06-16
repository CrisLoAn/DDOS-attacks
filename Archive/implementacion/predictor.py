#!/usr/bin/python3

import csv
import threading
import time
from collections import deque

# Predictor variables
alpha = 0.5
T_n = 256
Tau_n = 256
previous_frame_size = 256  # Use snake_case for variable naming

# Config variables
registros_file = '/usr/local/src/DDOs-folder/config/registros.csv'  # Replace with the actual path to your CSV file
current_frame = []
predictions = deque(maxlen=300)
packet_counts = deque(maxlen=300)  # Mantener un historial de 60 segundos de datos
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
    global alpha
    global current_frame
    global previous_frame_size
    tau_n1 = alpha * tn + (1 - alpha) * tau_n
    update_predictor_variables(len(current_frame), int(tau_n1))
    previous_frame_size = tn
    return int(tau_n1)

def update_predictor_variables(current_load, prediction):
    global Tau_n
    global T_n
    T_n = current_load
    Tau_n = prediction

def predict_request():
    global T_n
    global Tau_n
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




# Create and start the prediction thread
thread = threading.Thread(target=prediction_thread)
thread.start()

# Main program continues running and can perform other tasks
try:
    while True:
        # Main thread can perform other tasks or just wait
        time.sleep(1)
except KeyboardInterrupt:
    # Stop the prediction thread gracefully on interrupt
    stop_thread = True
    thread.join()
    print("Prediction thread stopped.")
