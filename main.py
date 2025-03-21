import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import httpx
import threading
import pyperclip
import time
import config

# Liste des sources d'API disponibles
API_SOURCES = {
    "crt.sh": True,
    "SecurityTrails": bool(config.securitytrails_API),
    "VirusTotal": bool(config.virustotal_api_key),
    "BinaryEdge": bool(config.binaryedge_api_key),
    "Shodan": bool(config.shodan_api_key),
    "Censys": bool(config.censys_api_id and config.censys_api_secret),
}

# Stockage des résultats
result_data = set()

# Fonction pour scanner les sous-domaines
def scan_subdomains():
    domain = entry.get().strip()
    if not domain:
        messagebox.showwarning("Erreur", "Veuillez entrer un domaine valide.")
        return

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"🔍 Scanning {domain}...\n")

    selected_sources = [src for src, var in checkboxes.items() if var.get()]
    if not selected_sources:
        messagebox.showwarning("Erreur", "Veuillez sélectionner au moins une source.")
        return

    result_data.clear()

    def fetch_subdomains(source):
        try:
            if source == "crt.sh":
                url = f"https://crt.sh/?q={domain}&output=json"
                response = httpx.get(url, timeout=10)
                if response.status_code == 200:
                    subdomains = {entry["name_value"] for entry in response.json()}
                    result_data.update(subdomains)
            elif source == "SecurityTrails":
                url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                headers = {"APIKEY": config.securitytrails_API}
                response = httpx.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    subdomains = {f"{sub}.{domain}" for sub in response.json().get("subdomains", [])}
                    result_data.update(subdomains)
            elif source == "VirusTotal":
                url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
                headers = {"x-apikey": config.virustotal_api_key}
                response = httpx.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    subdomains = {sub["id"] for sub in response.json()["data"]}
                    result_data.update(subdomains)
            elif source == "BinaryEdge":
                url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
                headers = {"X-Key": config.binaryedge_api_key}
                response = httpx.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    subdomains = set(response.json().get("events", []))
                    result_data.update(subdomains)
            elif source == "Shodan":
                url = f"https://api.shodan.io/dns/domain/{domain}?key={config.shodan_api_key}"
                response = httpx.get(url, timeout=10)
                if response.status_code == 200:
                    subdomains = {sub["subdomain"] for sub in response.json().get("subdomains", [])}
                    result_data.update(subdomains)
            elif source == "Censys":
                url = "https://search.censys.io/api/v1/search/certificates"
                auth = (config.censys_api_id, config.censys_api_secret)
                data = {"query": domain, "fields": ["parsed.names"], "page": 1}
                response = httpx.post(url, auth=auth, json=data, timeout=10)
                if response.status_code == 200:
                    subdomains = {name for entry in response.json()["results"] for name in entry["parsed.names"]}
                    result_data.update(subdomains)

        except Exception as e:
            output_text.insert(tk.END, f"⚠️ {source} failed: {e}\n")

    threads = [threading.Thread(target=fetch_subdomains, args=(src,), daemon=True) for src in selected_sources]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    output_text.insert(tk.END, "\n".join(result_data) + "\n")

# Fonction pour télécharger les résultats
def save_results():
    if not result_data:
        messagebox.showwarning("Erreur", "Aucun résultat à sauvegarder.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Fichier texte", "*.txt")])
    if file_path:
        with open(file_path, "w") as f:
            f.write("\n".join(result_data))
        messagebox.showinfo("Succès", f"Résultats sauvegardés dans {file_path}")

# Fonction pour coller du presse-papier avec délai
def paste_from_clipboard():
    time.sleep(1)  # Délai pour permettre la mise à jour du presse-papier
    clipboard_text = pyperclip.paste()

    print(f"Contenu du presse-papier: '{clipboard_text}'")  # Débogage

    if clipboard_text:
        entry.delete(0, tk.END)  # Clear the entry before pasting
        entry.insert(tk.END, clipboard_text)  # Paste the clipboard content
    else:
        messagebox.showwarning("Erreur", "Le presse-papier est vide ou invalide.")

# Fonction pour afficher le clavier virtuel
def show_virtual_keyboard():
    keyboard_frame.pack(side=tk.BOTTOM, fill=tk.X)

# Fonction pour insérer du texte depuis le clavier virtuel
def insert_character(char):
    if char == "DEL":
        entry.delete(len(entry.get()) - 1, tk.END)  # Suppression du dernier caractère
    else:
        entry.insert(tk.END, char)

# Interface GUI
root = tk.Tk()
root.title("Scanner de sous-domaines")
root.configure(bg="#222")

# Champ d'entrée du domaine
entry = tk.Entry(root, font=("Arial", 14), width=30, bg="#333", fg="#0f0", insertbackground="white")
entry.pack(pady=10, padx=10)
entry.bind("<FocusIn>", lambda e: show_virtual_keyboard())

# Bouton pour coller du texte
paste_button = tk.Button(root, text="Coller", command=paste_from_clipboard, bg="#444", fg="white", relief="raised", width=10)
paste_button.pack(pady=5)

# Zone de sélection des APIs
checkboxes = {}
api_frame = tk.Frame(root, bg="#222")
for source, enabled in API_SOURCES.items():
    var = tk.BooleanVar(value=enabled)
    checkboxes[source] = var
    tk.Checkbutton(api_frame, text=source, variable=var, bg="#222", fg="white", selectcolor="#008000").pack(anchor="w")
api_frame.pack(pady=10)

# Bouton Scan
scan_button = tk.Button(root, text="Scanner", command=scan_subdomains, font=("Arial", 14), bg="#008000", fg="white", relief="raised")
scan_button.pack(pady=10)

# Zone d'affichage des résultats
output_text = scrolledtext.ScrolledText(root, width=50, height=10, bg="#111", fg="#0f0", insertbackground="white")
output_text.pack(padx=10)

# Bouton Télécharger
save_button = tk.Button(root, text="Télécharger", command=save_results, font=("Arial", 14), bg="#555", fg="white", relief="raised")
save_button.pack(pady=10)

# Clavier virtuel
keyboard_frame = tk.Frame(root, bg="#222")

# Définir les clés et les lignes
keys = [
    "azertyuiop",
    "qsdfghjklm",
    "wxcvbn.,/",
    "0123456789:!?;"
]

# Ajouter chaque ligne
for row in keys:
    row_frame = tk.Frame(keyboard_frame, bg="#222")  # Création d'une ligne
    for key in row:
        action = lambda x=key: insert_character(x)
        btn = tk.Button(row_frame, text=key, width=3, height=2, command=action, bg="#333", fg="white")
        btn.pack(side=tk.LEFT)  # Placer les boutons horizontalement
    row_frame.pack()  # Empiler les lignes les unes sur les autres

# Ajouter la touche "DEL"
del_button = tk.Button(keyboard_frame, text="DEL", width=3, height=2, command=lambda: insert_character("DEL"), bg="#333", fg="white")
del_button.pack(side=tk.LEFT)  # Placer le bouton de suppression
keyboard_frame.pack(side=tk.BOTTOM, fill=tk.X)

root.mainloop()
