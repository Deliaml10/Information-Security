# main.py
import threading
import time

from application_1 import run_app1
from application_2 import run_app2
from application_3 import run_app3

def main():
    # Iniciar App3 (Verificador)
    print("[MAIN] Starting App3 (Verifier)...")
    t3 = threading.Thread(target=run_app3, daemon=True)
    t3.start()
    time.sleep(0.5)

    # Primera vez: no preguntar, no modificar
    primera_vez = True

    if primera_vez:
        tamper = False
        print("[MAIN] First execution: the signature will not be modified.")
    else:
        resp = input("[MAIN] Do you want to modify the signature in App2? (y/n): ").lower().strip()
        tamper = resp == 'y'

    # Iniciar App2 (Proxy)
    print("[MAIN] Starting App2 (Proxy)...")
    t2 = threading.Thread(target=run_app2, args=(tamper,), daemon=True)
    t2.start()
    time.sleep(0.5)

    # Obtener mensaje del usuario
    message = input("[MAIN] Enter the message to sign: ").strip()
    run_app1(message)

    t2.join()
    t3.join()

if __name__ == "__main__":
    main()
