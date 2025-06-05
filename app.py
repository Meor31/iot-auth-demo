# app.py
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import time
import random
from twilio.rest import Client # Assurez-vous d'installer: pip install twilio
import uuid # Pour générer des tokens uniques

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'une_cle_tres_secrete_par_defaut_a_changer')

# --- Configuration Twilio ---
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', "VOTRE_TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', "VOTRE_TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER', "VOTRE_NUMERO_TWILIO")

twilio_client = None
if TWILIO_ACCOUNT_SID != "VOTRE_TWILIO_ACCOUNT_SID" and TWILIO_AUTH_TOKEN != "VOTRE_TWILIO_AUTH_TOKEN" and TWILIO_PHONE_NUMBER != "VOTRE_NUMERO_TWILIO":
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        print("Client Twilio initialisé.")
    except Exception as e:
        print(f"Erreur lors de l'initialisation du client Twilio: {e}")
        twilio_client = None
else:
    print("Identifiants Twilio non configurés ou valeurs par défaut non modifiées. Le service SMS sera désactivé.")

def send_sms(to_phone_number, message_body):
    """Envoie un SMS via Twilio."""
    if twilio_client and TWILIO_PHONE_NUMBER and to_phone_number:
        try:
            message = twilio_client.messages.create(
                to=to_phone_number,
                from_=TWILIO_PHONE_NUMBER,
                body=message_body
            )
            print(f"SMS envoyé à {to_phone_number}: {message_body}")
            return True
        except Exception as e:
            print(f"Échec de l'envoi du SMS à {to_phone_number}: {e}")
            return False
    else:
        print("Client Twilio non configuré ou numéro(s) manquant(s). SMS non envoyé.")
        return False

# --- Configuration du fichier JSON ---
JSON_FILE_PATH = 'users_random_code.json'

def load_users():
    """Charge les données des utilisateurs depuis le fichier JSON."""
    if os.path.exists(JSON_FILE_PATH):
        try:
            with open(JSON_FILE_PATH, 'r') as f:
                data = json.load(f)
                # S'assurer que les champs nécessaires existent pour les anciens utilisateurs
                for user_data in data.values():
                     if 'enabled_devices' not in user_data or not isinstance(user_data['enabled_devices'], list):
                         user_data['enabled_devices'] = []
                     if 'phone_number' not in user_data:
                         user_data['phone_number'] = None
                return data
        except Exception as e:
             print(f"Erreur lors du chargement de {JSON_FILE_PATH}: {e}")
             return {}
    return {}

def save_users(users_data):
    """Sauvegarde les données des utilisateurs dans le fichier JSON."""
    try:
        with open(JSON_FILE_PATH, 'w') as f:
            json.dump(users_data, f, indent=4)
    except Exception as e:
        print(f"Erreur lors de la sauvegarde de {JSON_FILE_PATH}: {e}")

users = load_users()
print(f"Chargé {len(users)} utilisateurs depuis {JSON_FILE_PATH}")

# --- Gestion de l'état d'authentification temporaire ---
# Status: 'password_correct', 'awaiting_device_code', 'awaiting_user_code_entry', 'success', 'fail'
auth_states = {}
STATE_TIMEOUT = 300 # Durée de validité d'un état en secondes (5 minutes)

# Stocke le dernier timestamp de polling pour chaque appareil d'un utilisateur
device_last_seen = {}
# Temps en secondes après lequel un appareil est considéré hors ligne
# Doit être supérieur à POLLING_INTERVAL_SECONDS de l'ESP32 pour éviter les faux négatifs
DEVICE_TIMEOUT = 20 # secondes

def cleanup_expired_states():
    """Nettoie les états d'authentification temporaires expirés."""
    current_time = time.time()
    # Utiliser list(auth_states.items()) pour éviter RuntimeError si le dict change pendant l'itération
    expired_users = [username for username, data in list(auth_states.items()) if current_time > data.get('timestamp', 0) + STATE_TIMEOUT]
    for username in expired_users:
        print(f"Nettoyage de l'état expiré pour {username} (statut: {auth_states.get(username, {}).get('status')})")
        if username in auth_states:
            del auth_states[username]
        # Optionnel: Nettoyer aussi les entrées device_last_seen
        if username in device_last_seen:
             del device_last_seen[username]

def is_device_online(username, device_type):
    """Vérifie si un appareil spécifique pour un utilisateur est considéré en ligne."""
    current_time = time.time()
    if username in device_last_seen and device_type in device_last_seen[username]:
        # Vérifie si le dernier "vu" est dans le délai imparti
        return current_time < device_last_seen[username][device_type] + DEVICE_TIMEOUT
    return False

# --- Routes pour l'interface utilisateur ---
@app.route('/')
def index():
    # Page de login avec lien vers l'inscription
    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Connexion Compte Cloud</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:400px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1,h2{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-primary{background-color:#007bff;border:none;transition:background-color 0.2s;}.btn-primary:hover{background-color:#0056b3;}.alert{margin-top:20px;}</style></head>
        <body><div class="container"><h1>Accès Cloud</h1><h2>Connexion</h2>
        <form action="/login" method="post"><div class="mb-3"><label for="username" class="form-label">Nom d'utilisateur:</label><input type="text" class="form-control" id="username" name="username" required></div>
        <div class="mb-3"><label for="password" class="form-label">Mot de passe:</label><input type="password" class="form-control" id="password" name="password" required></div>
        <button type="submit" class="btn btn-primary w-100">Se Connecter</button></form>
        <p class="text-center mt-3"><a href="/register">Nouveau? S'inscrire ici.</a></p>
        <div id="login-status" class="alert d-none" role="alert"></div></div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.querySelector('form[action="/login"]').addEventListener('submit', async function(event) {
                event.preventDefault(); const form = event.target; const formData = new FormData(form);
                const response = await fetch(form.action, { method: form.method, body: formData });
                const result = await response.json(); const statusDiv = document.getElementById('login-status');
                statusDiv.innerText = result.message; statusDiv.className = 'alert'; /* Reset classes */
                if (result.status === 'fail') statusDiv.classList.add('alert-danger');
                else if (result.status === '2fa_required') statusDiv.classList.add('alert-info');
                else statusDiv.classList.add('alert-warning'); /* Default/other states */
                statusDiv.classList.remove('d-none');
                if (result.status === '2fa_required' && result.redirect_url) {
                    setTimeout(() => { window.location.href = result.redirect_url; }, 2000);
                }
            });
        </script></body></html>
    ''')

@app.route('/register')
def register_page():
    # Page d'inscription
    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Inscription</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:500px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-success{background-color:#28a745;border:none;transition:background-color 0.2s;}.btn-success:hover{background-color:#1e7e34;}.alert{margin-top:20px;}</style></head>
        <body><div class="container"><h1>Inscription</h1>
        <form action="/register" method="post">
            <div class="mb-3"><label for="username" class="form-label">Nom d'utilisateur:</label><input type="text" class="form-control" id="username" name="username" required></div>
            <div class="mb-3"><label for="password" class="form-label">Mot de passe:</label><input type="password" class="form-control" id="password" name="password" required></div>
            <div class="mb-3"><label for="phone_number" class="form-label">Numéro de téléphone (pour SMS, format +12223334444):</label><input type="tel" class="form-control" id="phone_number" name="phone_number" placeholder="+33612345678" required><small class="form-text text-muted">Requis pour recevoir les codes 2FA.</small></div>
            <div class="mb-3"><label class="form-label">Choisissez vos dispositifs 2FA (au moins un):</label><br>
                <div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" id="device_pi" name="device" value="pi"><label class="form-check-label" for="device_pi">Raspberry Pi</label></div>
                <div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" id="device_esp32" name="device" value="esp32"><label class="form-check-label" for="device_esp32">ESP32</label></div>
            </div>
            <button type="submit" class="btn btn-success w-100">S'inscrire</button>
        </form>
        <p class="text-center mt-3"><a href="/">Retour à la connexion.</a></p>
        <div id="register-status" class="alert d-none" role="alert"></div></div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.querySelector('form[action="/register"]').addEventListener('submit', async function(event) {
                event.preventDefault(); const form = event.target; const formData = new FormData(form);
                const response = await fetch(form.action, { method: form.method, body: formData });
                const result = await response.json(); const statusDiv = document.getElementById('register-status');
                statusDiv.innerText = result.message; statusDiv.className = 'alert'; /* Reset classes */
                if (response.ok) statusDiv.classList.add('alert-success'); else statusDiv.classList.add('alert-danger');
                statusDiv.classList.remove('d-none');
            });
        </script></body></html>
    ''')

@app.route('/register', methods=['POST'])
def register():
    global users
    username = request.form.get('username')
    password = request.form.get('password')
    phone_number = request.form.get('phone_number')
    enabled_devices = request.form.getlist('device') # Récupère une liste de dispositifs cochés

    if not username or not password or not phone_number:
        return jsonify({"message": "Nom d'utilisateur, mot de passe et numéro de téléphone requis"}), 400
    if not enabled_devices: # S'assurer qu'au moins un dispositif est choisi
         return jsonify({"message": "Veuillez sélectionner au moins un dispositif 2FA"}), 400
    if username in users:
        return jsonify({"message": "Nom d'utilisateur déjà existant"}), 409

    # Pas de génération de secret TOTP ici car on utilise un code aléatoire de l'appareil
    users[username] = {
        'password_hash': generate_password_hash(password),
        'enabled_devices': enabled_devices,
        'phone_number': phone_number # Stocker le numéro de téléphone
    }
    save_users(users)
    print(f"Utilisateur {username} enregistré. Dispositifs 2FA: {enabled_devices}. Numéro: {phone_number}")
    return jsonify({"message": "Utilisateur enregistré avec succès !"}), 201


@app.route('/login', methods=['POST'])
def login():
    cleanup_expired_states() # Nettoyer les anciens états
    username = request.form.get('username')
    password = request.form.get('password')
    user = users.get(username)

    if not user or not check_password_hash(user['password_hash'], password):
        print(f"Échec de connexion (identifiants invalides) pour {username}.")
        # Envoyer un SMS d'alerte pour échec de connexion si l'utilisateur existe et a un numéro
        if user and user.get('phone_number'):
             send_sms(user['phone_number'], f"Alerte de sécurité: Tentative de connexion échouée (identifiants) pour votre compte {username}.")
        if username: # Enregistrer l'état d'échec pour l'utilisateur s'il existe
             auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
        return jsonify({"status": "fail", "message": "Nom d'utilisateur ou mot de passe invalide"}), 401

    # Mot de passe correct, procéder à la 2FA
    enabled_devices = user.get('enabled_devices', [])
    if not enabled_devices:
         print(f"Aucun appareil 2FA activé pour l'utilisateur {username}.")
         if user.get('phone_number'): send_sms(user['phone_number'], f"Tentative de connexion échouée: Aucun appareil 2FA activé pour votre compte {username}.")
         auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
         return jsonify({"status": "fail", "message": "Aucun appareil 2FA configuré pour votre compte"}), 400

    # Vérifier quels appareils activés sont actuellement "en ligne"
    online_devices = [device for device in enabled_devices if is_device_online(username, device)]
    print(f"Appareils activés pour {username}: {enabled_devices}. Appareils actuellement en ligne: {online_devices}")

    if not online_devices:
         message = f"Aucun de vos appareils 2FA ({', '.join(enabled_devices)}) n'est actuellement en ligne. Veuillez vérifier vos appareils."
         print(f"{message} pour l'utilisateur {username}")
         if user.get('phone_number'): send_sms(user['phone_number'], f"Tentative de connexion échouée: {message}")
         auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
         return jsonify({"status": "fail", "message": message}), 400

    # Choisir un appareil au hasard parmi ceux qui sont en ligne
    chosen_device = random.choice(online_devices)
    print(f"Appareil 2FA choisi aléatoirement pour {username}: {chosen_device}")

    browser_token = str(uuid.uuid4()) # Token pour lier la session navigateur
    auth_states[username] = {
        'status': 'awaiting_device_code', # Le serveur attend que l'appareil envoie un code
        'device': chosen_device,          # L'appareil qui doit envoyer le code
        'browser_token': browser_token,
        'received_code': None,            # Le code reçu de l'appareil sera stocké ici
        'timestamp': time.time()
    }
    print(f"État pour {username} mis à jour: awaiting_device_code (appareil attendu: {chosen_device})")
    
    # Informer l'utilisateur d'attendre et fournir l'URL de redirection
    return jsonify({
        "status": "2fa_required",
        "message": f"Mot de passe correct. Le serveur va maintenant demander un code à votre appareil {chosen_device}. Veuillez attendre le SMS.",
        "redirect_url": url_for('verify_code_page', token=browser_token, _external=True) # Rediriger vers la page de saisie du code
    }), 200


@app.route('/verify_code_page') # Anciennement verify_totp_page
def verify_code_page():
    browser_token = request.args.get('token')
    username = None
    # Trouver l'état de l'utilisateur basé sur le token du navigateur
    for user_iter, state_data_iter in auth_states.items():
        if state_data_iter.get('browser_token') == browser_token:
            username = user_iter
            break

    if not username or username not in auth_states or time.time() > auth_states[username].get('timestamp', 0) + STATE_TIMEOUT:
        print(f"Accès à verify_code_page échoué: Token navigateur invalide ou état expiré pour token {browser_token}.")
        if username and username in auth_states: del auth_states[username] # Nettoyer l'état si expiré
        return "Requête invalide ou expirée. Veuillez recommencer la connexion.", 400

    state_data = auth_states[username]
    current_status = state_data['status']
    device_in_charge = state_data.get('device', 'sélectionné') # L'appareil qui doit fournir le code
    message_to_user = f"En attente que votre appareil {device_in_charge} envoie le code..."
    
    if current_status == 'awaiting_user_code_entry': # Si le code de l'appareil a été reçu par le serveur
        message_to_user = f"Code reçu de votre appareil {device_in_charge}. Veuillez saisir le code que vous avez reçu par SMS."
    elif current_status == 'awaiting_device_code': # Le serveur attend toujours le code de l'appareil
         message_to_user = f"Le serveur attend que votre appareil {device_in_charge} génère et envoie un code. Veuillez patienter pour le SMS."


    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vérification Code 2FA</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:400px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-primary{background-color:#007bff;border:none;}.btn-primary:hover{background-color:#0056b3;}.alert{margin-top:20px;}</style></head>
        <body><div class="container"><h1>Vérification Code 2FA</h1>
        <p class="text-center" id="status-message">{{ page_message }}</p>
        <form action="/verify_code" method="post">
            <input type="hidden" name="token" value="{{ browser_token_value }}">
            <div class="mb-3"><label for="device_name" class="form-label">Code provenant de l'appareil:</label><input type="text" class="form-control" id="device_name" name="device_name" value="{{ device_name_value }}" readonly required>
            <small class="form-text text-muted">Ce champ indique quel appareil a généré le code.</small></div>
            <div class="mb-3"><label for="auth_code" class="form-label">Code reçu par SMS:</label><input type="text" class="form-control" id="auth_code" name="auth_code" pattern="[0-9]{6}" title="Le code doit contenir 6 chiffres." required></div>
            <button type="submit" class="btn btn-primary w-100">Vérifier le Code</button>
        </form>
        <div id="verification-status" class="alert d-none" role="alert"></div></div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.querySelector('form[action="/verify_code"]').addEventListener('submit', async function(event) {
                event.preventDefault(); const form = event.target; const formData = new FormData(form);
                const response = await fetch(form.action, { method: form.method, body: formData });
                const result = await response.json(); const statusDiv = document.getElementById('verification-status');
                statusDiv.innerText = result.message; statusDiv.className = 'alert'; /* Reset classes */
                if (result.status === 'success') {
                    statusDiv.classList.add('alert-success');
                    if(result.redirect_url) setTimeout(() => { window.location.href = result.redirect_url; }, 2000);
                } else { statusDiv.classList.add('alert-danger'); }
                statusDiv.classList.remove('d-none');
            });
            // Optionnel: Polling pour mettre à jour #status-message si le code de l'appareil est reçu par le serveur
            // pendant que cette page est ouverte par l'utilisateur. Cela nécessiterait un autre endpoint.
        </script></body></html>
    ''', browser_token_value=browser_token, page_message=message_to_user, device_name_value=device_in_charge)


@app.route('/verify_code', methods=['POST']) # Anciennement verify_totp
def verify_code():
    cleanup_expired_states()
    browser_token = request.form.get('token')
    auth_code_user_input = request.form.get('auth_code') # Code saisi par l'utilisateur
    # device_name_user_input = request.form.get('device_name') # Nom de l'appareil (maintenant readonly)

    username = None
    for user_iter, state_data_iter in auth_states.items():
        if state_data_iter.get('browser_token') == browser_token:
            username = user_iter
            break

    if not username or username not in auth_states or time.time() > auth_states[username].get('timestamp', 0) + STATE_TIMEOUT:
        print(f"Vérification code échouée: Token navigateur invalide ou état expiré pour token {browser_token}.")
        if username and username in auth_states: del auth_states[username]
        return jsonify({"status": "fail", "message": "Session de vérification expirée ou invalide. Veuillez recommencer la connexion."}), 400

    state_data = auth_states[username]
    received_device_code = state_data.get('received_code') # Code envoyé par l'appareil IoT
    # chosen_device_by_server = state_data.get('device') # Appareil que le serveur avait choisi

    # Vérifier si le serveur attend bien la saisie du code par l'utilisateur et si un code a été reçu de l'appareil
    if state_data['status'] != 'awaiting_user_code_entry' or not received_device_code:
         print(f"Vérification code échouée pour {username}: Code de l'appareil non encore reçu par le serveur, ou état incorrect ({state_data['status']}).")
         return jsonify({"status": "fail", "message": "Le code de votre appareil n'a pas encore été reçu par le serveur ou l'état de la session est incorrect. Veuillez attendre le SMS et réessayer."}), 400

    # Vérifier si le code saisi par l'utilisateur correspond au code reçu de l'appareil IoT
    if auth_code_user_input == received_device_code:
        # 2FA réussie
        print(f"Vérification code 2FA réussie pour {username}.")
        auth_states[username]['status'] = 'success'
        auth_states[username]['timestamp'] = time.time() # Mettre à jour le timestamp pour la session
        user_data = users.get(username) # Pour le numéro de téléphone
        if user_data and user_data.get('phone_number'):
             send_sms(user_data['phone_number'], f"Connexion réussie à votre compte cloud (via {state_data.get('device')}).")

        return jsonify({"status": "success", "message": "Vérification 2FA réussie. Redirection vers votre espace cloud...", "redirect_url": url_for('cloud_space', _external=True)}), 200
    else:
        # Code saisi par l'utilisateur est invalide
        print(f"Vérification code 2FA échouée pour {username}: Code saisi ({auth_code_user_input}) invalide. Code attendu: {received_device_code}.")
        # auth_states[username]['status'] = 'fail' # Optionnel: marquer comme échec immédiatement
        # auth_states[username]['timestamp'] = time.time()
        user_data = users.get(username)
        if user_data and user_data.get('phone_number'):
             send_sms(user_data['phone_number'], f"Tentative de connexion échouée (code 2FA invalide saisi) pour votre compte cloud.")
        return jsonify({"status": "fail", "message": "Code de vérification invalide."}), 401

# --- Points de terminaison pour les appareils IoT ---

@app.route('/submit_device_code', methods=['POST']) # Anciennement submit_device_totp
def submit_device_code():
    cleanup_expired_states()
    data = request.get_json()
    username = data.get('username')
    device_type = data.get('device_type') # 'pi' ou 'esp32'
    code_from_device = data.get('code')   # Le code aléatoire généré par l'appareil

    print(f"Code '{code_from_device}' reçu de l'appareil {device_type} pour l'utilisateur {username}.")

    if not username or not device_type or not code_from_device:
        print("Soumission de code par appareil échouée: Données manquantes.")
        return jsonify({"status": "error", "message": "Données manquantes de l'appareil"}), 400

    state_data = auth_states.get(username)
    user_config = users.get(username) # Pour obtenir le numéro de téléphone

    # Vérifier si l'utilisateur existe, si une tentative est en attente de code de CET appareil
    if not user_config or not state_data or state_data['status'] != 'awaiting_device_code' or state_data.get('device') != device_type:
        print(f"Soumission de code non attendue pour {username} depuis {device_type} (état serveur: {state_data.get('status') if state_data else 'aucun état'}, appareil attendu: {state_data.get('device') if state_data else 'aucun'}).")
        if user_config and user_config.get('phone_number'):
            send_sms(user_config['phone_number'], f"Alerte de sécurité: Tentative de soumission de code 2FA inattendue depuis un appareil ({device_type}) pour votre compte cloud {username}.")
        return jsonify({"status": "fail", "message": "Aucune demande de code en attente de cet appareil ou utilisateur inconnu"}), 400

    # Le code est aléatoire, le serveur l'accepte tel quel.
    print(f"Code aléatoire '{code_from_device}' reçu et accepté de l'appareil {device_type} pour {username}.")
    auth_states[username]['received_code'] = code_from_device
    auth_states[username]['status'] = 'awaiting_user_code_entry' # Le serveur attend maintenant que l'utilisateur saisisse ce code
    auth_states[username]['timestamp'] = time.time() # Mettre à jour le timestamp

    # Envoyer le code reçu (de l'appareil) par SMS à l'utilisateur
    sms_message = f"Votre code de vérification pour le compte cloud (généré par {device_type}): {code_from_device}"
    if user_config.get('phone_number'):
        send_sms(user_config['phone_number'], sms_message)
    else:
        print(f"Aucun numéro de téléphone trouvé pour {username}. SMS non envoyé. Le code était: {code_from_device}")

    return jsonify({"status": "success", "message": "Code reçu par le serveur et SMS envoyé à l'utilisateur."}), 200


@app.route('/check_auth_status', methods=['POST'])
def check_auth_status():
    cleanup_expired_states()
    data = request.get_json()
    username = data.get('username')
    device_type = data.get('device_type') # Pour loguer quel appareil interroge

    if not username or not device_type:
        return jsonify({"status": "error", "message": "Nom d'utilisateur ou type d'appareil manquant"}), 400

    # Mettre à jour le timestamp de la dernière vue pour cet appareil
    if username not in device_last_seen:
        device_last_seen[username] = {}
    device_last_seen[username][device_type] = time.time()
    # print(f"Appareil {device_type} pour {username} vu à {time.ctime(device_last_seen[username][device_type])}") # Optionnel pour débogage

    state_data = auth_states.get(username)

    if state_data and time.time() < state_data.get('timestamp', 0) + STATE_TIMEOUT:
        status = state_data['status']
        response_data = {"status": status}

        # Si le serveur attend un code de CET appareil spécifique
        if status == 'awaiting_device_code' and state_data.get('device') == device_type:
             response_data['action'] = 'generate_random_code_and_submit' # Demander à l'appareil de générer un code
             response_data['message'] = f"Le serveur attend que vous ({device_type}) génériez un code aléatoire et le soumettiez."
             print(f"Statut pour {username} ({device_type}): {status} - Action: generate_random_code_and_submit")
        elif status in ['success', 'fail']: # Si l'authentification est terminée (succès ou échec)
             response_data['action'] = 'stop_polling'
             response_data['message'] = f"Processus d'authentification terminé ({status}). Vous pouvez arrêter d'interroger pour cette session."
             print(f"Statut pour {username} ({device_type}): {status} - Action: stop_polling")
        else: # 'awaiting_user_code_entry' ou autre état où l'appareil doit juste attendre
             response_data['action'] = 'wait'
             response_data['message'] = f"En attente ({status}). Aucune action requise de l'appareil pour le moment."
             # print(f"Statut pour {username} ({device_type}): {status} - Action: wait") # Optionnel pour débogage

        return jsonify(response_data), 200
    else:
        # Si aucun état récent, ou état expiré
        # print(f"Aucun état d'authentification actif ou récent pour {username} lors du check par {device_type}") # Optionnel
        return jsonify({"status": "not_authenticated", "action": "wait", "message": "Aucun état d'authentification actif pour l'utilisateur"}), 200

# --- Route pour l'espace cloud (exemple de page protégée) ---
@app.route('/cloud_space')
def cloud_space():
    cleanup_expired_states()
    authenticated_user = None
    current_time = time.time()
    # Chercher un utilisateur dont l'état est 'success' et non expiré
    for user_iter, state_data_iter in list(auth_states.items()): # itérer sur une copie
        if state_data_iter.get('status') == 'success' and \
           current_time < state_data_iter.get('timestamp', 0) + STATE_TIMEOUT: # Vérifier aussi l'expiration ici
            authenticated_user = user_iter
            # Optionnel: Invalider l'état de succès après le premier accès pour plus de sécurité
            # Ou mieux, utiliser un vrai système de session Flask.
            # if user_iter in auth_states:
            #     del auth_states[user_iter] # Nettoyer l'état après accès
            break

    if authenticated_user:
        return render_template_string(f'''
            <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Espace Cloud Sécurisé</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>body{{font-family:sans-serif; background-color:#e9ecef; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0;}}
            .container{{text-align:center; background-color:#fff; padding:40px; border-radius:10px; box-shadow:0 0 20px rgba(0,0,0,0.1);}}
            h1{{color:#007bff; margin-bottom:20px;}} p{{font-size:1.2em;}}
            .btn-logout{{background-color:#dc3545; color:white; margin-top:30px; padding: 10px 20px; text-decoration:none; border-radius:5px;}}
            .btn-logout:hover{{background-color:#c82333;}}</style></head>
            <body><div class="container"><h1>Bienvenue dans votre Espace Cloud, {authenticated_user}!</h1>
            <p>Ceci est votre espace personnel sécurisé.</p>
            <a href="/" class="btn btn-logout">Se déconnecter (Retour à l'accueil)</a>
            </div></body></html>
        ''')
    else:
        print("Accès à /cloud_space refusé: non authentifié ou session 2FA expirée.")
        return redirect(url_for('index'))


if __name__ == '__main__':
    # Pour le déploiement sur des plateformes comme Render, la commande de démarrage (ex: gunicorn)
    # est généralement spécifiée dans un Procfile.
    # Pour les tests locaux:
    # app.run(debug=True, host='0.0.0.0', port=5001) # Utiliser un port différent si le port 5000 est pris
    print("Serveur Flask (mode code aléatoire) démarré.")
    print("Configurez vos variables d'environnement TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER pour les SMS.")
    print("Si elles ne sont pas configurées, les SMS ne seront pas envoyés, surveillez la console du serveur pour les codes.")

