#!/usr/bin/env python3
import time
import predictor as pred

try:
    while True:
        packet_count = len(pred.current_frame)  # Llama a la función packet_counts
        print(f"PC -> {packet_count}")
        time.sleep(1)
        
except KeyboardInterrupt:
    print("Interrupción del usuario. Finalizando...")
