#!/usr/bin/python3

import pandas as pd
from keras._tf_keras.keras.models import load_model

# Ruta del archivo CSV
ruta_csv = "/usr/local/src/DDOs-folder/config/registros.csv"

# Leer el archivo CSV
datos = pd.read_csv(ruta_csv)

# Cargar el modelo
modelo = load_model('./DNN.h5')

# Preparar los datos de entrada para hacer predicciones
# Suponiendo que necesitas ciertas columnas como características para hacer predicciones
caracteristicas = datos[['src',	'dst', 'pktcount', 'bytecount', 'dur', 'Protocol', 'port_no', 'tx_bytes', 'rx_bytes','tx_kbps','rx_kbps','tot_kbps']]

# Escalar las características si es necesario (asegúrate de usar el mismo escalador que se usó durante el entrenamiento)
# scaler = ...

# Hacer predicciones
predicciones = modelo.predict(caracteristicas)

# Mostrar las predicciones
print(predicciones)
