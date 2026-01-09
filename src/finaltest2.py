import tkinter as tk
import hashlib
import numpy as np
import os
import json
import datetime  # <-- IMPORT AJOUTÉ

# =========================
# SDitH - Fonctions de base
# =========================

def genere_sk(n=3072, w=64):
    # vecteur binaire de longueur n avec exactement w bits à 1
    binary_sk = np.zeros(n, dtype=np.uint8)
    position = np.random.choice(n, w, replace=False)
    binary_sk[position] = 1
    return binary_sk

def generate_H(m=1536, n=3072):
    # matrice publique H (m x n) sur GF(2)
    seed_H = os.urandom(16)
    binary_seed = ''.join(f'{byte:08b}' for byte in seed_H)
    # shake = hashlib.shake_128
    """print(seed_H)
    print(binary_seed)
    """
    # SHAKE on a 1536*3072)/8= 589824
    taille = (m * n)/ 8
    shake = hashlib.shake_128(seed_H).digest(589824)
    binary_shake = ''.join(f'{byte:08b}' for byte in shake)
    """print(shake)
    print(binary_shake)
    """
    # generation de H
    # on utilise la version binaire de shake pour generer H
    # cela ce fait en transformant binary_shake en matrice 1536*3072

    H = np.array(list(binary_shake), dtype=int).reshape(m, n)
   
    return H

def syndrome(H, e):
    return (H @ e) % 2

# =========================
# SDitH - Signature (maquette)
# =========================

def hash_message_bytes(data: bytes, algo: str = "sha256") -> bytes:
    if algo == "sha256":
        return hashlib.sha256(data).digest()
    elif algo == "shake128":
        return hashlib.shake_128(data).digest(32)
    elif algo == "shake256":
        return hashlib.shake_256(data).digest(32)
    else:
        raise ValueError("Algorithme de hash non supporté")

def fs_challenge(commit_bytes: bytes, msg_digest: bytes, rounds: int = 16) -> bytes:
    h = hashlib.sha256()
    h.update(commit_bytes)
    h.update(msg_digest)
    h.update(rounds.to_bytes(2, "big"))
    return h.digest()

def sign_sdith(H, sk, msg_bytes, rounds=16, algo="sha256"):
    digest = hash_message_bytes(msg_bytes, algo=algo)

    s_pub = syndrome(H, sk)  # clé publique (syndrome)

    commits = []
    masks = []
    for _ in range(rounds):
        r = np.random.randint(0, 2, size=H.shape[1], dtype=np.uint8)
        t = (H @ r) % 2
        commits.append(t.tolist())
        masks.append(r.tolist())

    commit_bytes = json.dumps(commits).encode("utf-8")
    challenge = fs_challenge(commit_bytes, digest, rounds=rounds)
    c_bits = np.unpackbits(np.frombuffer(challenge, dtype=np.uint8))[:rounds]

    responses = []
    for i in range(rounds):
        r_vec = np.array(masks[i], dtype=np.uint8)
        y = r_vec if c_bits[i] == 0 else (r_vec ^ sk)
        responses.append(y.tolist())

    return {
        "rounds": rounds,
        "algo": algo,
        "commits": commits,
        "responses": responses,
        "challenge": challenge.hex(),
        "public_syndrome": s_pub.tolist(),
        "params": {"m": H.shape[0], "n": H.shape[1]},
    }

def verify_sdith_with_sender_pk(H, msg_bytes, signature, sender_pk):
    rounds = signature["rounds"]
    algo = signature["algo"]
    commits = [np.array(t, dtype=np.uint8) for t in signature["commits"]]
    responses = [np.array(y, dtype=np.uint8) for y in signature["responses"]]
    params = signature["params"]

    if params["m"] != H.shape[0] or params["n"] != H.shape[1]:
        return False

    digest = hash_message_bytes(msg_bytes, algo=algo)
    commit_bytes = json.dumps(signature["commits"]).encode("utf-8")
    expected_challenge = fs_challenge(commit_bytes, digest, rounds=rounds).hex()
    if expected_challenge != signature["challenge"]:
        return False

    c_bits = np.unpackbits(np.frombuffer(bytes.fromhex(signature["challenge"]), dtype=np.uint8))[:rounds]
    s_sender = np.array(sender_pk, dtype=np.uint8)

    for i in range(rounds):
        Hy = (H @ responses[i]) % 2
        if c_bits[i] == 0:
            if not np.array_equal(Hy, commits[i]):
                return False
        else:
            if not np.array_equal(Hy, (commits[i] ^ s_sender)):
                return False

    return True

# =========================
# Réseau interne (boîtes)
# =========================

MAILBOX = {}

def deliver_message(dest_name, payload):
    MAILBOX[dest_name] = payload

def fetch_message(dest_name):
    return MAILBOX.get(dest_name, None)

# =========================
# Fenêtre utilisateur améliorée
# =========================

class UserWindow:
    def __init__(self, root, name, H, sk, pk_map):
        self.name = name
        self.H = H
        self.sk = sk
        self.pk_map = pk_map
        self.signature_steps = []  # Pour stocker les étapes de signature
        self.verification_steps = []  # Pour stocker les étapes de vérification

        self.win = tk.Toplevel(root)
        self.win.title(f"{name} - Interface SDitH")
        self.win.geometry("1000x800")

        # Frame pour les contrôles d'entrée
        input_frame = tk.Frame(self.win)
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(input_frame, text="Chemin du fichier texte à signer").pack(anchor=tk.W)
        self.entry_file = tk.Entry(input_frame, width=70)
        self.entry_file.pack(fill=tk.X, pady=2)

        tk.Label(input_frame, text="Nom de la fenêtre destinataire (User1/User2/User3)").pack(anchor=tk.W)
        self.entry_dest = tk.Entry(input_frame, width=70)
        self.entry_dest.pack(fill=tk.X, pady=2)

        # Frame pour les boutons
        button_frame = tk.Frame(self.win)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(button_frame, text="Signer et Envoyer", command=self.valider, 
                 bg="lightblue", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Consulter et Vérifier", command=self.consulter, 
                 bg="lightgreen", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Effacer les logs", command=self.effacer_logs, 
                 bg="lightcoral").pack(side=tk.RIGHT, padx=5)

        # Frame principale pour les logs
        main_log_frame = tk.Frame(self.win)
        main_log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Frame pour les logs de signature (côté gauche)
        left_frame = tk.Frame(main_log_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        tk.Label(left_frame, text="ÉTAPES DE SIGNATURE", font=("Arial", 11, "bold"), 
                bg="lightblue").pack(fill=tk.X)
        
        # Zone de logs pour la signature
        self.signature_log_frame = tk.Frame(left_frame)
        self.signature_log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.signature_canvas = tk.Canvas(self.signature_log_frame)
        scrollbar_y = tk.Scrollbar(self.signature_log_frame, orient=tk.VERTICAL, 
                                  command=self.signature_canvas.yview)
        scrollbar_x = tk.Scrollbar(self.signature_log_frame, orient=tk.HORIZONTAL, 
                                  command=self.signature_canvas.xview)
        
        self.signature_text = tk.Text(self.signature_canvas, wrap=tk.WORD, 
                                     yscrollcommand=scrollbar_y.set,
                                     xscrollcommand=scrollbar_x.set,
                                     font=("Courier", 9), bg="white")
        
        scrollbar_y.config(command=self.signature_text.yview)
        scrollbar_x.config(command=self.signature_text.xview)
        
        self.signature_canvas.create_window((0, 0), window=self.signature_text, anchor=tk.NW)
        self.signature_canvas.config(yscrollcommand=scrollbar_y.set,
                                    xscrollcommand=scrollbar_x.set)
        
        self.signature_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.signature_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Frame pour les logs de vérification (côté droit)
        right_frame = tk.Frame(main_log_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        tk.Label(right_frame, text="ÉTAPES DE VÉRIFICATION", font=("Arial", 11, "bold"), 
                bg="lightgreen").pack(fill=tk.X)
        
        # Zone de logs pour la vérification
        self.verification_log_frame = tk.Frame(right_frame)
        self.verification_log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.verification_canvas = tk.Canvas(self.verification_log_frame)
        scrollbar_y2 = tk.Scrollbar(self.verification_log_frame, orient=tk.VERTICAL, 
                                   command=self.verification_canvas.yview)
        scrollbar_x2 = tk.Scrollbar(self.verification_log_frame, orient=tk.HORIZONTAL, 
                                   command=self.verification_canvas.xview)
        
        self.verification_text = tk.Text(self.verification_canvas, wrap=tk.WORD,
                                        yscrollcommand=scrollbar_y2.set,
                                        xscrollcommand=scrollbar_x2.set,
                                        font=("Courier", 9), bg="white")
        
        scrollbar_y2.config(command=self.verification_text.yview)
        scrollbar_x2.config(command=self.verification_text.xview)
        
        self.verification_canvas.create_window((0, 0), window=self.verification_text, anchor=tk.NW)
        self.verification_canvas.config(yscrollcommand=scrollbar_y2.set,
                                       xscrollcommand=scrollbar_x2.set)
        
        self.verification_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y2.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x2.pack(side=tk.BOTTOM, fill=tk.X)
        self.verification_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Frame pour le contenu du fichier (bas de la fenêtre)
        bottom_frame = tk.Frame(self.win)
        bottom_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)

        tk.Label(bottom_frame, text="CONTENU DU FICHIER", font=("Arial", 11, "bold"),
                bg="lightyellow").pack(fill=tk.X)
        
        self.file_content_text = tk.Text(bottom_frame, height=8, wrap=tk.WORD,
                                        font=("Courier", 9), bg="white")
        scrollbar_content = tk.Scrollbar(bottom_frame, command=self.file_content_text.yview)
        self.file_content_text.config(yscrollcommand=scrollbar_content.set)
        
        self.file_content_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_content.pack(side=tk.RIGHT, fill=tk.Y)

        # Configurer les tags pour la coloration syntaxique
        self.signature_text.tag_config("title", foreground="blue", font=("Courier", 10, "bold"))
        self.signature_text.tag_config("step", foreground="green", font=("Courier", 9, "bold"))
        self.signature_text.tag_config("success", foreground="darkgreen", font=("Courier", 9, "bold"))
        self.signature_text.tag_config("error", foreground="red", font=("Courier", 9, "bold"))
        self.signature_text.tag_config("data", foreground="purple")
        self.signature_text.tag_config("hash", foreground="orange")
        
        self.verification_text.tag_config("title", foreground="blue", font=("Courier", 10, "bold"))
        self.verification_text.tag_config("step", foreground="green", font=("Courier", 9, "bold"))
        self.verification_text.tag_config("success", foreground="darkgreen", font=("Courier", 9, "bold"))
        self.verification_text.tag_config("error", foreground="red", font=("Courier", 9, "bold"))
        self.verification_text.tag_config("data", foreground="purple")
        self.verification_text.tag_config("hash", foreground="orange")

    def log_signature_step(self, message, tag=""):
        """Ajoute une étape dans le log de signature"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")  # <-- CORRECTION ICI
        log_entry = f"[{timestamp}] {message}\n"
        self.signature_text.insert(tk.END, log_entry, tag)
        self.signature_text.see(tk.END)
        self.signature_steps.append(log_entry)

    def log_verification_step(self, message, tag=""):
        """Ajoute une étape dans le log de vérification"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")  # <-- CORRECTION ICI
        log_entry = f"[{timestamp}] {message}\n"
        self.verification_text.insert(tk.END, log_entry, tag)
        self.verification_text.see(tk.END)
        self.verification_steps.append(log_entry)

    def afficher_contenu_fichier(self, filepath):
        """Affiche le contenu du fichier dans la zone dédiée"""
        self.file_content_text.delete(1.0, tk.END)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                self.file_content_text.insert(1.0, content)
                self.log_signature_step(f"Contenu du fichier lu ({len(content)} caractères)", "data")
        except UnicodeDecodeError:
            try:
                with open(filepath, "r", encoding="latin-1") as f:
                    content = f.read()
                    self.file_content_text.insert(1.0, content)
                    self.log_signature_step(f"Contenu du fichier lu avec encodage latin-1 ({len(content)} caractères)", "data")
            except Exception as e:
                self.file_content_text.insert(1.0, f"<Impossible de lire le fichier: {e}>")
                self.log_signature_step(f"Erreur de lecture du fichier: {e}", "error")
        except Exception as e:
            self.file_content_text.insert(1.0, f"<Erreur: {e}>")
            self.log_signature_step(f"Erreur d'ouverture du fichier: {e}", "error")

    def valider(self):
        """Signe un fichier et l'envoie au destinataire"""
        # Effacer les anciens logs de signature
        self.signature_text.delete(1.0, tk.END)
        self.signature_steps = []
        
        filepath = self.entry_file.get().strip()
        dest = self.entry_dest.get().strip()
        
        if not filepath or not dest:
            self.log_signature_step("Erreur: chemin et destinataire requis.", "error")
            return

        self.log_signature_step(f"Début de la signature pour {dest}", "title")
        self.log_signature_step(f"Fichier: {filepath}", "step")
        
        # Afficher le contenu du fichier
        self.afficher_contenu_fichier(filepath)

        try:
            with open(filepath, "rb") as f:
                msg_bytes = f.read()
            self.log_signature_step(f"Fichier chargé: {len(msg_bytes)} octets", "step")
        except Exception as e:
            self.log_signature_step(f"Erreur d'ouverture du fichier: {e}", "error")
            return

        try:
            self.log_signature_step("Phase 1: Calcul du hash du message", "step")
            digest = hash_message_bytes(msg_bytes, algo="sha256")
            self.log_signature_step(f"Hash SHA-256: {digest.hex()[:32]}...", "hash")
            
            self.log_signature_step("Phase 2: Calcul du syndrome public", "step")
            s_pub = syndrome(self.H, self.sk)
            self.log_signature_step(f"Syndrome calculé (16 premiers bits): {s_pub[:16]}...", "data")
            
            self.log_signature_step("Phase 3: Génération des engagements (16 rounds)", "step")
            commits = []
            masks = []
            for i in range(16):
                r = np.random.randint(0, 2, size=self.H.shape[1], dtype=np.uint8)
                t = (self.H @ r) % 2
                commits.append(t.tolist())
                masks.append(r.tolist())
                if i < 3:  # Afficher seulement les 3 premiers rounds pour éviter la surcharge
                    self.log_signature_step(f"  Round {i+1}: engagement généré", "data")
            
            self.log_signature_step("Phase 4: Transformation Fiat-Shamir", "step")
            commit_bytes = json.dumps(commits).encode("utf-8")
            challenge = fs_challenge(commit_bytes, digest, rounds=16)
            c_bits = np.unpackbits(np.frombuffer(challenge, dtype=np.uint8))[:16]
            self.log_signature_step(f"Challenge généré: {challenge.hex()[:32]}...", "hash")
            self.log_signature_step(f"Bits du challenge: {c_bits}", "data")
            
            self.log_signature_step("Phase 5: Génération des réponses", "step")
            responses = []
            for i in range(16):
                r_vec = np.array(masks[i], dtype=np.uint8)
                y = r_vec if c_bits[i] == 0 else (r_vec ^ self.sk)
                responses.append(y.tolist())
                if i < 3:
                    self.log_signature_step(f"  Round {i+1}: réponse générée", "data")
            
            signature = {
                "rounds": 16,
                "algo": "sha256",
                "commits": commits,
                "responses": responses,
                "challenge": challenge.hex(),
                "public_syndrome": s_pub.tolist(),
                "params": {"m": self.H.shape[0], "n": self.H.shape[1]},
            }
            
            payload = (filepath, signature, self.name)
            deliver_message(dest, payload)
            
            self.log_signature_step("="*50, "title")
            self.log_signature_step("SIGNATURE RÉUSSIE !", "success")
            self.log_signature_step(f"Signature envoyée à {dest}", "success")
            self.log_signature_step(f"Taille de la signature: ~{len(json.dumps(signature))} octets", "data")
            self.log_signature_step("="*50, "title")
            
        except Exception as e:
            self.log_signature_step(f"Erreur lors de la signature: {e}", "error")

    def consulter(self):
        """Vérifie une signature reçue"""
        # Effacer les anciens logs de vérification
        self.verification_text.delete(1.0, tk.END)
        self.verification_steps = []
        
        item = fetch_message(self.name)
        if item is None:
            self.log_verification_step("Aucun message reçu.", "error")
            return

        filepath, signature, sender = item
        
        self.log_verification_step(f"Début de la vérification", "title")
        self.log_verification_step(f"Expéditeur: {sender}", "step")
        self.log_verification_step(f"Fichier: {filepath}", "step")
        
        # Afficher le contenu du fichier
        self.afficher_contenu_fichier(filepath)
        
        s_sender = self.pk_map.get(sender, None)
        if s_sender is None:
            self.log_verification_step(f"Clé publique de {sender} introuvable.", "error")
            return

        try:
            with open(filepath, "rb") as f:
                msg_bytes = f.read()
            self.log_verification_step(f"Fichier chargé: {len(msg_bytes)} octets", "step")
        except Exception as e:
            self.log_verification_step(f"Erreur d'ouverture du fichier: {e}", "error")
            return

        # Vérification détaillée
        self.log_verification_step("Étape 1: Vérification des paramètres", "step")
        params = signature["params"]
        if params["m"] != self.H.shape[0] or params["n"] != self.H.shape[1]:
            self.log_verification_step("  ✗ Paramètres incompatibles", "error")
            return
        self.log_verification_step("  ✓ Paramètres compatibles", "success")
        
        self.log_verification_step("Étape 2: Calcul du hash du message", "step")
        digest = hash_message_bytes(msg_bytes, algo=signature["algo"])
        self.log_verification_step(f"  Hash calculé: {digest.hex()[:32]}...", "hash")
        
        self.log_verification_step("Étape 3: Vérification du challenge Fiat-Shamir", "step")
        commit_bytes = json.dumps(signature["commits"]).encode("utf-8")
        expected_challenge = fs_challenge(commit_bytes, digest, rounds=signature["rounds"]).hex()
        if expected_challenge != signature["challenge"]:
            self.log_verification_step("  ✗ Challenge invalide", "error")
            return
        self.log_verification_step("  ✓ Challenge valide", "success")
        
        self.log_verification_step("Étape 4: Vérification des réponses (16 rounds)", "step")
        c_bits = np.unpackbits(np.frombuffer(bytes.fromhex(signature["challenge"]), dtype=np.uint8))[:signature["rounds"]]
        commits = [np.array(t, dtype=np.uint8) for t in signature["commits"]]
        responses = [np.array(y, dtype=np.uint8) for y in signature["responses"]]
        s_sender_array = np.array(s_sender, dtype=np.uint8)
        
        all_rounds_valid = True
        for i in range(signature["rounds"]):
            Hy = (self.H @ responses[i]) % 2
            if c_bits[i] == 0:
                if not np.array_equal(Hy, commits[i]):
                    self.log_verification_step(f"  Round {i+1}: ✗ Échec (c=0)", "error")
                    all_rounds_valid = False
                    break
                else:
                    if i < 3:  # Afficher seulement les 3 premiers
                        self.log_verification_step(f"  Round {i+1}: ✓ Succès (c=0)", "success")
            else:
                if not np.array_equal(Hy, (commits[i] ^ s_sender_array)):
                    self.log_verification_step(f"  Round {i+1}: ✗ Échec (c=1)", "error")
                    all_rounds_valid = False
                    break
                else:
                    if i < 3:  # Afficher seulement les 3 premiers
                        self.log_verification_step(f"  Round {i+1}: ✓ Succès (c=1)", "success")
        
        if all_rounds_valid:
            self.log_verification_step("="*50, "title")
            self.log_verification_step("VÉRIFICATION RÉUSSIE !", "success")
            self.log_verification_step(f"Fichier authentifié de {sender}", "success")
            self.log_verification_step("Signature valide", "success")
            self.log_verification_step("="*50, "title")
            
            # Afficher le contenu du fichier
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        self.file_content_text.insert(tk.END, line)
            except UnicodeDecodeError:
                self.file_content_text.insert(tk.END, "<Fichier binaire ou encodage incompatible>")
        else:
            self.log_verification_step("="*50, "title")
            self.log_verification_step("VÉRIFICATION ÉCHOUÉE !", "error")
            self.log_verification_step("Signature invalide", "error")
            self.log_verification_step("="*50, "title")

    def effacer_logs(self):
        """Efface tous les logs"""
        self.signature_text.delete(1.0, tk.END)
        self.verification_text.delete(1.0, tk.END)
        self.file_content_text.delete(1.0, tk.END)
        self.signature_steps = []
        self.verification_steps = []

# =========================
# Initialisation et lancement
# =========================

def main():
    root = tk.Tk()
    root.withdraw()

    m, n, w = 1536, 3072, 64

    H = generate_H(m=m, n=n)

    sk1 = genere_sk(n=n, w=w)
    sk2 = genere_sk(n=n, w=w)
    sk3 = genere_sk(n=n, w=w)

    pk1 = syndrome(H, sk1).tolist()
    pk2 = syndrome(H, sk2).tolist()
    pk3 = syndrome(H, sk3).tolist()

    pk_map = {"User1": pk1, "User2": pk2, "User3": pk3}

    UserWindow(root, "User1", H, sk1, pk_map)
    UserWindow(root, "User2", H, sk2, pk_map)
    UserWindow(root, "User3", H, sk3, pk_map)

    root.mainloop()

if __name__ == "__main__":
    main()
