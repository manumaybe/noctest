# Importación de librerías necesarias
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import csv
import threading
import webbrowser
from datetime import datetime
import pytz

# Lista de antivirus considerados principales
antivirus_principales = [
    "mcafee", "kaspersky", "sentinelone", "paloalto", "cortex",
    "crowdstrike", "trendmicro", "fortiedr"
]

# Lista de API keys de VirusTotal
api_keys = [
    'b486e1ee4be94a28877d298ba3c9c7a286e750eba811f1c4650f1c3505b248e3',
    '814a4c6bc99a5065f5877fd372904bbb1bfddcd3e2b4617396d8fb9ca6cfd3a4',
    '043ac09840187ef9581c7c1126a0c92efab241b32c684fe41025dd70258c0165',
    'df6ae6329b79b2b1ed074c54b971405eea04a1f2ed03e0e444cab7f25df102e8',
    '0eba2e3541479ac27e08d1b05da8290229c4cc8099fd19c896b895966b894ab2',
]

# Lista global
data_global = []


def analizar_hash():
    hashes = hash_entry.get("1.0", tk.END).strip().splitlines()
    if not hashes:
        messagebox.showerror("Error", "Por favor ingrese al menos un hash.")
        return

    progress_label.config(text="Analizando hashes...")
    progress_bar.grid(row=6, column=0, padx=10, pady=10, sticky="nsew")
    progress_bar["value"] = 0
    progress_bar["maximum"] = len(hashes)

    for row in tree.get_children():
        tree.delete(row)
    data_global.clear()


    threading.Thread(target=analizar_hash_thread, args=(hashes,)).start()

def analizar_hash_thread(hashes):
    url = 'https://www.virustotal.com/api/v3/files/'

    for idx, hash_value in enumerate(hashes):
        for api_key in api_keys:
            headers = {'x-apikey': api_key}
            response = requests.get(url + hash_value, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']
                scans = attributes['last_analysis_results']

                malicious = False
                principales = []
                otros = []

                for scan in scans.values():
                    if scan['category'] == 'malicious':
                        malicious = True
                        engine = scan['engine_name'].lower()
                        if any(principal in engine for principal in antivirus_principales):
                            principales.append(scan['engine_name'])
                        else:
                            otros.append(scan['engine_name'])

                # Veredicto del hash
                verdict = "Malicioso" if malicious else "Benigno"
                color = "red" if malicious else "green"
                vt_link = f"https://www.virustotal.com/gui/file/{hash_value}"

                
                family = []
                for key in ['sha256', 'sha1', 'md5', 'meaningful_name', 'humanhash', 'sha3_384']:
                    family.append(attributes.get(key, "No existe"))
                family_info = "\n".join([f"{k.upper()}: {v}" for k, v in zip(
                    ['sha256', 'sha1', 'md5', 'filename', 'humanhash', 'sha3_384'], family)])

                
                last_analysis = attributes.get("last_analysis_date", None)
                if last_analysis:
                    dt = datetime.fromtimestamp(last_analysis, pytz.timezone("Etc/GMT+5"))
                    last_analysis_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    last_analysis_str = "No disponible"

                data_global.append({
                    "hash": hash_value,
                    "veredicto": verdict,
                    "principales": ', '.join(principales),
                    "otros": otros,
                    "familia": family_info,
                    "ultima_vez": last_analysis_str,
                    "enlace": vt_link
                })

                tree.insert('', 'end',
                    values=(hash_value, verdict, ', '.join(principales), vt_link, last_analysis_str, "Más info"),
                    tags=(color,)
                )
                tree.tag_configure(color, foreground=color)
                break
            elif response.status_code == 403:
                continue

        progress_bar["value"] = idx + 1
        root.update_idletasks()

    progress_label.config(text="Análisis completado.")
    root.after(2000, lambda: progress_bar.grid_forget())

def mostrar_mas_info(event):
    item = tree.identify_row(event.y)
    col = tree.identify_column(event.x)
    if not item or col != '#6':
        return

    index = tree.index(item)
    data = data_global[index]

    ventana_info = tk.Toplevel(root)
    ventana_info.title("Información adicional del hash analizado")
    ventana_info.geometry("600x400")

    text_box = tk.Text(ventana_info, wrap="word")
    text_box.pack(fill="both", expand=True, padx=10, pady=10)

    text_box.insert(tk.END, "Familia del hash:\n")
    text_box.insert(tk.END, data["familia"] + "\n\n")
    text_box.insert(tk.END, "AV Principales:\n")
    text_box.insert(tk.END, data["principales"] + "\n\n")
    text_box.insert(tk.END, "AV Otros:\n")
    text_box.insert(tk.END, ', '.join(data["otros"]))

    text_box.config(state=tk.NORMAL)
    text_box.bind("<Control-a>", lambda e: (text_box.tag_add(tk.SEL, "1.0", tk.END), "break"))
    text_box.bind("<Control-c>", lambda e: (text_box.event_generate("<<Copy>>"), "break"))

def abrir_enlace(event):
    item = tree.identify_row(event.y)
    col = tree.identify_column(event.x)
    if col == '#4' and item:
        enlace = tree.item(item)['values'][3]
        webbrowser.open_new_tab(enlace)

def exportar_a_csv():
    if not data_global:
        messagebox.showwarning("Advertencia", "No hay datos para exportar.")
        return

    with open("analisis_hashes.csv", mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Hash", "Veredicto", "AV Principales", "AV Otros", "Link a VT", "Familia", "Última vez analizado"])
        for dato in data_global:
            writer.writerow([
                dato["hash"], dato["veredicto"], dato["principales"],
                ', '.join(dato["otros"]), dato["enlace"], dato["familia"], dato["ultima_vez"]
            ])
    messagebox.showinfo("Éxito", "Datos exportados a analisis_hashes.csv")

# Configuración de la ventana principal
root = tk.Tk()
root.title("Analizador de Hashes con VirusTotal")
root.state('normal')  # Ventana con botones normales de minimizar/maximizar/cerrar
root.geometry("1280x720")

# Contenedor principal
frame = tk.Frame(root, padx=10, pady=10)
frame.pack(fill=tk.BOTH, expand=True)

# Configuraciones del grid para que todo se escale bien
frame.grid_columnconfigure(0, weight=1)
frame.grid_rowconfigure(0, weight=1)
frame.grid_rowconfigure(1, weight=0)
frame.grid_rowconfigure(2, weight=1)

# Entrada de hashes
hash_label = tk.Label(frame, text="Ingrese los hashes (uno por línea):")
hash_label.grid(row=0, column=0, sticky="w")

hash_entry = tk.Text(frame, height=10, width=150)
hash_entry.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

# Botón para analizar
analyze_button = tk.Button(frame, text="Analizar", command=analizar_hash)
analyze_button.grid(row=2, column=0, sticky="ew", pady=5)

# Tabla para mostrar los resultados
columns = ("Hash", "Veredicto", "Principales", "Enlace a VT", "Última vez", "Más info")
tree = ttk.Treeview(frame, columns=columns, show="headings")
tree.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
frame.grid_rowconfigure(3, weight=10)

# Configuración de las columnas
for col in columns:
    tree.heading(col, text=col)

tree.column("Hash", width=250, anchor="w")
tree.column("Veredicto", width=100, anchor="center")
tree.column("Principales", width=200, anchor="w")
tree.column("Enlace a VT", width=200, anchor="w")
tree.column("Última vez", width=150, anchor="center")
tree.column("Más info", width=100, anchor="center")

# Eventos para el enlace y botón más info
tree.bind("<Button-1>", abrir_enlace)
tree.bind("<Button-1>", mostrar_mas_info, add='+')

# Botón para exportar a CSV
export_button = tk.Button(frame, text="Exportar a CSV", command=exportar_a_csv)
export_button.grid(row=4, column=0, sticky="ew", pady=5)

# Etiqueta y barra de progreso
progress_label = tk.Label(frame, text="")
progress_label.grid(row=5, column=0)

progress_bar = ttk.Progressbar(frame, orient="horizontal", mode="determinate")
progress_bar.grid(row=6, column=0, pady=5, sticky="ew")
progress_bar.grid_remove()

root.mainloop()









