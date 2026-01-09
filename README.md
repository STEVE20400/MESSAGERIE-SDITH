# MESSAGERIE-SDITH
LE PROGRAMME UTILISE LE SCHEMA DE SIGNATURE SDITH POUR SIGNERUNE MESSAGE ET LENVEYER EN L'OCURENCE LE NOM D'UN FICHIER

1. PRÉSENTATION GÉNÉRALECe programme simule un système de messagerie sécurisé entre trois utilisateurs (User1, User2, User3). Il implémente le schéma de signature post-quantique SDitH, basé sur la difficulté du décodage de syndrome sur le corps fini GF(2). Le logiciel permet de signer des fichiers, de les envoyer virtuellement via un réseau interne et de vérifier leur authenticité.
   
2. INSTALLATION ET PRÉREQUIS
   
   Le programme nécessite Python 3.x et les bibliothèques suivantes :
      Tkinter : Pour l'interface graphique (inclus par défaut avec Python).
      NumPy : Pour les calculs matriciels et la manipulation des vecteurs            binaires.
      lA commande d'installation : pip install numpy

      Les autres bibliothèques ( hashlib, os, json, datetime) sont incluses dans la bibliothèque standard de Python.
      
3. EXÉCUTION DU PROGRAMME
   Pour lancer l'application, exécutez la commande suivante :
   python finaltest2.py
Cela ouvrira simultanément trois fenêtres représentant les interfaces de User1, User2 et User3.

4. GUIDE D'UTILISATION DES BOUTONS
   Signer et Envoyer :Lit le fichier spécifié, calcule le hash SHA-256 du message et génère 16 rounds d'engagements (commits).Applique la transformation de Fiat-Shamir pour générer un challenge et produit les réponses correspondantes.Transfère le paquet complet au destinataire via la MAILBOX.

5.LES DONNÉES RÉELLEMENT ENVOYÉES (LE PAYLOAD)
  Lors d'un envoi, l'objet transmis au destinataire est un tuple contenant :Le chemin du fichier (Chaîne de caractères).La Signature (Dictionnaire contenant : rounds, algo de hash, liste des 16 commits, liste des 16 réponses, le challenge hexadécimal, le syndrome public de l'expéditeur et les paramètres m/n).Le nom de l'expéditeur (Pour identifier la clé publique à utiliser).

   Consulter et Vérifier :Récupère le message en attente pour l'utilisateur actuel.Vérifie l'intégrité du challenge et recalcule les relations matricielles ($Hy = commits$ ou $Hy = commits \oplus syndrome$) pour chaque round.Affiche le résultat de l'authentification (Succès ou Échec).
   Effacer les logs : Réinitialise l'affichage des zones de texte (Signature, Vérification et Contenu du fichier).
   
7. EXPLICATION DES FONCTIONS ET PARAMÈTRES
   ->genere_sk(n, w) : Crée la clé privée (vecteur binaire).n (3072) : Longueur du vecteur ; w (64) : Nombre de bits à 1.Retour : Vecteur binaire sk.
   
   ->generate_H(m, n) : Génère la matrice de parité publique via SHAKE-128.m (1536) : Nombre de lignes ; n (3072) : Nombre de colonnes.Retour : Matrice binaire H.

   ->syndrome(H, e) : Calcule la clé publique ou le syndrome.H : Matrice ; e : Vecteur d'erreur.Retour : Produit $H \times e \pmod 2$.
   ->sign_sdith(...) / verify_sdith_with_sender_pk(...) : Fonctions de haut niveau gérant le protocole d'identification transformé en signature:
   
   ->sign_sdith(H, sk, msg_bytes, rounds=16, algo="sha256") : 
      Génère une signature SDitH.

      Paramètres:
          H (np.array): Matrice publique
          sk (np.array): Clé secrète
          msg_bytes (bytes): Message à signer
          rounds (int): Nombre de tours (16)
          algo (str): Algorithme de hash
      
      Retourne un dictionnaire contenant:
          - "rounds": Nombre de tours
          - "algo": Algorithme utilisé
          - "commits": Liste des engagements (16 listes de bits)
          - "responses": Liste des réponses (16 listes de bits)
          - "challenge": Challenge hexadécimal
          - "public_syndrome": Syndrome public (clé)
          - "params": {"m": m, "n": n}

   ->verify_sdith_with_sender_pk(H, msg_bytes, signature, sender_pk):
   
          
      Vérifie une signature SDitH.
      
      Paramètres:
          H (np.array): Matrice publique
          msg_bytes (bytes): Message original
          signature (dict): Signature à vérifier
          sender_pk (list): Clé publique de l'expéditeur
      
      Retourne:
          bool: True si signature valide, False sinon
      
    
->  deliver_message(dest_name, payload):
    
  Envoie un message à un destinataire.

  Paramètres:
    dest_name (str): Nom du destinataire ("User1", "User2", "User3")
    payload (tuple): Données à envoyer

  Effet:
    Stocke le payload dans MAILBOX[dest_name]

->fetch_message(dest_name):
    Récupère un message pour un destinataire.

  Paramètres:
    dest_name (str): Nom du destinataire

  Retourne:
    tuple ou None: Message s'il existe, None sinon

### maintenant dans la classe UserWindow
  ->__init__(root, name, H, sk, pk_map):
    Initialise l'interface utilisateur
    Configure les zones de texte, boutons et défilement
  ->log_signature_step(message, tag):
    Ajoute un message au log de signature
    Inclut un timestamp et une coloration syntaxique
  ->log_verification_step(message, tag):
    Ajoute un message au log de vérification
  ->afficher_contenu_fichier(filepath)
      Lit et affiche le contenu d'un fichier
      Gère différents encodages (UTF-8, latin-1)

8-Problèmes courants :

  ->ModuleNotFoundError: No module named 'numpy'
    pip install numpy
  ->Fichier introuvable
    Vérifiez le chemin du fichier
    Utilisez des chemins absolus si nécessaire
  ->Encodage non supporté
    Le programme supporte UTF-8 et latin-1
    Pour d'autres encodages, modifiez afficher_contenu_fichier()







