# app.py
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
# pyotp n'est plus utilisé pour la génération/vérification principale, mais peut être gardé si d'autres usages existent.
# Pour ce flux spécifique, il n'est plus central.
# import pyotp
import base64 # Peut être utilisé pour d'autres encodages si besoin, mais plus pour le secret TOTP.
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
JSON_FILE_PATH = 'users_random_code.json' # Nom de fichier différent pour éviter conflits

def load_users():
    if os.path.exists(JSON_FILE_PATH):
        try:
            with open(JSON_FILE_PATH, 'r') as f:
                data = json.load(f)
                for user_data in data.values():
                     if 'enabled_devices' not in user_data or not isinstance(user_data['enabled_devices'], list):
                         user_data['enabled_devices'] = []
                     if 'phone_number' not in user_data:
                         user_data['phone_number'] = None
                     # totp_secret n'est plus utilisé dans ce flux
                return data
        except Exception as e:
             print(f"Erreur lors du chargement de {JSON_FILE_PATH}: {e}")
             return {}
    return {}

def save_users(users_data):
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
STATE_TIMEOUT = 300 # 5 minutes
device_last_seen = {}
DEVICE_TIMEOUT = 20 # Appareil considéré hors ligne après 20s (doit être > POLLING_INTERVAL de l'ESP32)

def cleanup_expired_states():
    current_time = time.time()
    expired_users = [username for username, data in list(auth_states.items()) if current_time > data['timestamp'] + STATE_TIMEOUT]
    for username in expired_users:
        print(f"Nettoyage de l'état expiré pour {username} (statut: {auth_states.get(username, {}).get('status')})")
        if username in auth_states:
            del auth_states[username]
        if username in device_last_seen:
             del device_last_seen[username]

def is_device_online(username, device_type):
    current_time = time.time()
    if username in device_last_seen and device_type in device_last_seen[username]:
        return current_time < device_last_seen[username][device_type] + DEVICE_TIMEOUT
    return False

# --- Routes UI (inchangées pour la structure, mais les messages peuvent varier) ---
@app.route('/')
def index():
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
                statusDiv.innerText = result.message; statusDiv.className = 'alert'; // Reset classes
                if (result.status === 'fail') statusDiv.classList.add('alert-danger');
                else if (result.status === '2fa_required') statusDiv.classList.add('alert-info');
                else statusDiv.classList.add('alert-warning'); // Default/other states
                statusDiv.classList.remove('d-none');
                if (result.status === '2fa_required' && result.redirect_url) {
                    setTimeout(() => { window.location.href = result.redirect_url; }, 2000);
                }
            });
        </script></body></html>
    ''')

@app.route('/register')
def register_page():
    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Inscription</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:500px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-success{background-color:#28a745;border:none;transition:background-color 0.2s;}.btn-success:hover{background-color:#1e7e34;}.alert{margin-top:20px;}</style></head>
        <body><div class="container"><h1>Inscription</h1>
        <form action="/register" method="post">
            <div class="mb-3"><label for="username" class="form-label">Nom d'utilisateur:</label><input type="text" class="form-control" id="username" name="username" required></div>
            <div class="mb-3"><label for="password" class="form-label">Mot de passe:</label><input type="password" class="form-control" id="password" name="password" required></div>
            <div class="mb-3"><label for="phone_number" class="form-label">Numéro de téléphone (pour SMS, format +12223334444):</label><input type="tel" class="form-control" id="phone_number" name="phone_number" placeholder="+12345678900" required><small class="form-text text-muted">Requis pour recevoir les codes 2FA.</small></div>
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
                statusDiv.innerText = result.message; statusDiv.className = 'alert'; // Reset classes
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
    enabled_devices = request.form.getlist('device')

    if not username or not password or not phone_number:
        return jsonify({"message": "Nom d'utilisateur, mot de passe et numéro de téléphone requis"}), 400
    if not enabled_devices:
         return jsonify({"message": "Veuillez sélectionner au moins un dispositif 2FA"}), 400
    if username in users:
        return jsonify({"message": "Nom d'utilisateur déjà existant"}), 409

    # Le secret TOTP n'est plus généré/stocké ici pour ce flux
    users[username] = {
        'password_hash': generate_password_hash(password),
        'enabled_devices': enabled_devices,
        'phone_number': phone_number
    }
    save_users(users)
    print(f"Utilisateur {username} enregistré. Dispositifs 2FA: {enabled_devices}.")
    return jsonify({"message": "Utilisateur enregistré avec succès !"}), 201

@app.route('/login', methods=['POST'])
def login():
    cleanup_expired_states()
    username = request.form.get('username')
    password = request.form.get('password')
    user = users.get(username)

    if not user or not check_password_hash(user['password_hash'], password):
        print(f"Échec de connexion (identifiants) pour {username}.")
        if user and user.get('phone_number'):
             send_sms(user['phone_number'], f"Tentative de connexion échouée (identifiants) pour votre compte {username}.")
        if username: auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
        return jsonify({"status": "fail", "message": "Nom d'utilisateur ou mot de passe invalide"}), 401

    enabled_devices = user.get('enabled_devices', [])
    if not enabled_devices:
         print(f"Aucun appareil 2FA activé pour {username}.")
         if user.get('phone_number'): send_sms(user['phone_number'], f"Connexion échouée: Aucun appareil 2FA activé pour {username}.")
         auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
         return jsonify({"status": "fail", "message": "Aucun appareil 2FA configuré"}), 400

    online_devices = [device for device in enabled_devices if is_device_online(username, device)]
    print(f"Appareils activés pour {username}: {enabled_devices}. Appareils en ligne: {online_devices}")

    if not online_devices:
         message = f"Aucun de vos appareils 2FA ({', '.join(enabled_devices)}) n'est actuellement en ligne."
         print(f"{message} pour {username}")
         if user.get('phone_number'): send_sms(user['phone_number'], f"Connexion échouée: {message}")
         auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
         return jsonify({"status": "fail", "message": message}), 400

    chosen_device = random.choice(online_devices)
    print(f"Appareil 2FA choisi pour {username}: {chosen_device}")
    browser_token = str(uuid.uuid4())
    auth_states[username] = {
        'status': 'awaiting_device_code', # Attend que l'appareil envoie un code aléatoire
        'device': chosen_device,
        'browser_token': browser_token,
        'received_code': None,
        'timestamp': time.time()
    }
    print(f"État pour {username}: awaiting_device_code (appareil: {chosen_device})")
    # Le message indique à l'utilisateur d'attendre la demande à l'appareil
    return jsonify({
        "status": "2fa_required",
        "message": f"Mot de passe correct. Le serveur va demander un code à votre appareil {chosen_device}. Attendez le SMS.",
        "redirect_url": url_for('verify_code_page', token=browser_token, _external=True)
    }), 200

@app.route('/verify_code_page') # Anciennement verify_totp_page
def verify_code_page():
    browser_token = request.args.get('token')
    username = None
    for user_iter, state_data_iter in auth_states.items():
        if state_data_iter.get('browser_token') == browser_token:
            username = user_iter
            break
    if not username or username not in auth_states or time.time() > auth_states[username]['timestamp'] + STATE_TIMEOUT:
        if username and username in auth_states: del auth_states[username]
        return "Requête invalide ou expirée. Veuillez recommencer.", 400

    state_data = auth_states[username]
    current_status = state_data['status']
    device_in_charge = state_data.get('device', 'sélectionné')
    message_to_user = f"Attente du code de l'appareil {device_in_charge}..."
    if current_status == 'awaiting_user_code_entry':
        message_to_user = f"Code reçu de l'appareil {device_in_charge}. Veuillez saisir le code reçu par SMS."

    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vérification Code 2FA</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:400px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-primary{background-color:#007bff;border:none;}.btn-primary:hover{background-color:#0056b3;}.alert{margin-top:20px;}</style></head>
        <body><div class="container"><h1>Vérification Code 2FA</h1>
        <p class="text-center" id="status-message">{{ page_message }}</p>
        <form action="/verify_code" method="post">
            <input type="hidden" name="token" value="{{ browser_token_value }}">
            <div class="mb-3"><label for="device_name" class="form-label">Nom de l'appareil (ex: esp32):</label><input type="text" class="form-control" id="device_name" name="device_name" value="{{ device_name_value }}" readonly required></div>
            <div class="mb-3"><label for="auth_code" class="form-label">Code reçu par SMS:</label><input type="text" class="form-control" id="auth_code" name="auth_code" pattern="[0-9]{6}" title="Code à 6 chiffres" required></div>
            <button type="submit" class="btn btn-primary w-100">Vérifier le Code</button>
        </form>
        <div id="verification-status" class="alert d-none" role="alert"></div></div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.querySelector('form[action="/verify_code"]').addEventListener('submit', async function(event) {
                event.preventDefault(); const form = event.target; const formData = new FormData(form);
                const response = await fetch(form.action, { method: form.method, body: formData });
                const result = await response.json(); const statusDiv = document.getElementById('verification-status');
                statusDiv.innerText = result.message; statusDiv.className = 'alert'; // Reset classes
                if (result.status === 'success') {
                    statusDiv.classList.add('alert-success');
                    if(result.redirect_url) setTimeout(() => { window.location.href = result.redirect_url; }, 2000);
                } else { statusDiv.classList.add('alert-danger'); }
                statusDiv.classList.remove('d-none');
            });
            // Optionnel: Polling pour mettre à jour #status-message si le code de l'appareil est reçu pendant que la page est ouverte
            // Cela nécessiterait un autre endpoint pour vérifier l'état spécifique pour le navigateur.
        </script></body></html>
    ''', browser_token_value=browser_token, page_message=message_to_user, device_name_value=device_in_charge)

@app.route('/verify_code', methods=['POST']) # Anciennement verify_totp
def verify_code():
    cleanup_expired_states()
    browser_token = request.form.get('token')
    # device_name_user_input = request.form.get('device_name') # Maintenant readonly, mais on le récupère quand même
    auth_code_user_input = request.form.get('auth_code')

    username = None
    for user_iter, state_data_iter in auth_states.items():
        if state_data_iter.get('browser_token') == browser_token:
            username = user_iter
            break
    if not username or username not in auth_states or time.time() > auth_states[username]['timestamp'] + STATE_TIMEOUT:
        if username and username in auth_states: del auth_states[username]
        return jsonify({"status": "fail", "message": "Session expirée. Recommencez."}), 400

    state_data = auth_states[username]
    received_device_code = state_data.get('received_code')
    chosen_device_by_server = state_data.get('device')

    if state_data['status'] != 'awaiting_user_code_entry' or not received_device_code:
         return jsonify({"status": "fail", "message": "Le code de l'appareil n'a pas encore été reçu ou l'état est incorrect. Attendez le SMS."}), 400

    if auth_code_user_input == received_device_code: # On ne vérifie plus device_name_user_input car il est pré-rempli et readonly
        print(f"Vérification code 2FA réussie pour {username}.")
        auth_states[username]['status'] = 'success'
        auth_states[username]['timestamp'] = time.time()
        user_data = users.get(username)
        if user_data and user_data.get('phone_number'):
             send_sms(user_data['phone_number'], f"Connexion réussie à votre compte cloud ({chosen_device_by_server}).")
        return jsonify({"status": "success", "message": "Vérification réussie! Redirection...", "redirect_url": url_for('cloud_space', _external=True)}), 200
    else:
        print(f"Vérification code 2FA échouée pour {username}: Code ({auth_code_user_input}) invalide.")
        # Ne pas changer l'état en 'fail' immédiatement pour permettre de réessayer si l'utilisateur a mal tapé.
        # L'état expirera naturellement. Si on veut un échec immédiat :
        # auth_states[username]['status'] = 'fail'
        # auth_states[username]['timestamp'] = time.time()
        user_data = users.get(username)
        if user_data and user_data.get('phone_number'):
             send_sms(user_data['phone_number'], f"Tentative de connexion échouée (code 2FA invalide) pour le compte {username}.")
        return jsonify({"status": "fail", "message": "Code invalide."}), 401

# --- Endpoints pour Appareils IoT ---
@app.route('/submit_device_code', methods=['POST']) # Anciennement submit_device_totp
def submit_device_code():
    cleanup_expired_states()
    data = request.get_json()
    username = data.get('username')
    device_type = data.get('device_type')
    code_from_device = data.get('code') # Changé de 'totp' à 'code'

    print(f"Code {code_from_device} reçu de l'appareil {device_type} pour l'utilisateur {username}.")
    if not username or not device_type or not code_from_device:
        return jsonify({"status": "error", "message": "Données manquantes"}), 400

    state_data = auth_states.get(username)
    user_config = users.get(username)

    if not user_config or not state_data or state_data['status'] != 'awaiting_device_code' or state_data.get('device') != device_type:
        print(f"Soumission de code non attendue pour {username} depuis {device_type}.")
        if user_config and user_config.get('phone_number'):
            send_sms(user_config['phone_number'], f"Alerte: Soumission de code 2FA inattendue de {device_type} pour {username}.")
        return jsonify({"status": "fail", "message": "Pas de demande de code en attente de cet appareil"}), 400

    # Le code est aléatoire, donc pas de vérification 'pyotp' ici.
    # On stocke juste le code reçu de l'appareil.
    print(f"Code aléatoire {code_from_device} reçu et accepté de {device_type} pour {username}.")
    auth_states[username]['received_code'] = code_from_device
    auth_states[username]['status'] = 'awaiting_user_code_entry'
    auth_states[username]['timestamp'] = time.time()

    sms_message = f"Votre code de vérification pour le compte cloud ({device_type}): {code_from_device}"
    if user_config.get('phone_number'):
        send_sms(user_config['phone_number'], sms_message)
    else:
        print(f"Aucun numéro de téléphone pour {username}, SMS non envoyé. Code: {code_from_device}")

    return jsonify({"status": "success", "message": "Code reçu par le serveur. SMS envoyé."}), 200

@app.route('/check_auth_status', methods=['POST'])
def check_auth_status():
    cleanup_expired_states()
    data = request.get_json()
    username = data.get('username')
    device_type = data.get('device_type')

    if not username or not device_type:
        return jsonify({"status": "error", "message": "Données manquantes"}), 400

    if username not in device_last_seen: device_last_seen[username] = {}
    device_last_seen[username][device_type] = time.time()

    state_data = auth_states.get(username)
    if state_data and time.time() < state_data['timestamp'] + STATE_TIMEOUT:
        status = state_data['status']
        response_data = {"status": status}
        # Changement ici: si on attend un code aléatoire de cet appareil
        if status == 'awaiting_device_code' and state_data.get('device') == device_type:
             response_data['action'] = 'generate_random_code_and_submit'
             response_data['message'] = "Le serveur attend que vous génériez un code aléatoire et le soumettiez."
             print(f"Statut pour {username} ({device_type}): {status} - Action: generate_random_code_and_submit")
        elif status in ['success', 'fail']:
             response_data['action'] = 'stop_polling'
             response_data['message'] = f"Processus terminé ({status}). Arrêtez le polling."
             print(f"Statut pour {username} ({device_type}): {status} - Action: stop_polling")
        else: # 'awaiting_user_code_entry' ou autre
             response_data['action'] = 'wait'
             response_data['message'] = f"En attente ({status}). Pas d'action requise de l'appareil pour le moment."
        return jsonify(response_data), 200
    else:
        return jsonify({"status": "not_authenticated", "action": "wait", "message": "Aucun état d'authentification actif"}), 200

@app.route('/cloud_space')
def cloud_space():
    cleanup_expired_states()
    authenticated_user = None
    current_time = time.time()
    for user_iter, state_data_iter in list(auth_states.items()):
        if state_data_iter.get('status') == 'success' and current_time < state_data_iter.get('timestamp', 0) + STATE_TIMEOUT:
            authenticated_user = user_iter
            # Pour la démo, on ne supprime pas l'état pour pouvoir recharger la page
            # Dans un vrai système, la session gérerait cela, et l'état pourrait être nettoyé.
            # if user_iter in auth_states: del auth_states[user_iter]
            break
    if authenticated_user:
        return render_template_string(f'''
            <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Espace Cloud</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>body{{font-family:sans-serif; background-color:#e9ecef; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0;}}
            .container{{text-align:center; background-color:#fff; padding:40px; border-radius:10px; box-shadow:0 0 20px rgba(0,0,0,0.1);}}
            h1{{color:#007bff; margin-bottom:20px;}} p{{font-size:1.2em;}}
            .btn-logout{{background-color:#dc3545; color:white; margin-top:30px;}}</style></head>
            <body><div class="container"><h1>Bienvenue, {authenticated_user}!</h1>
            <p>Ceci est votre espace cloud sécurisé.</p>
            <a href="/" class="btn btn-logout">Déconnexion (simulée)</a>
            </div></body></html>
        ''')
    else:
        print("Accès à cloud_space refusé: non authentifié ou session expirée.")
        return redirect(url_for('index'))

if __name__ == '__main__':
    # Attention: Pour Render, la commande de démarrage se fait via le Procfile (ex: gunicorn app:app)
    # app.run(debug=True, host='0.0.0.0', port=5001) # port 5001 pour éviter conflits locaux
    print("Serveur Flask démarré. Utilisez Gunicorn ou un autre serveur WSGI pour la production.")
    print(f"Pour tester localement, si vos variables d'environnement TWILIO sont configurées, le SMS devrait fonctionner.")
    print(f"Sinon, surveillez la console pour le code généré/reçu si le numéro de téléphone n'est pas fourni pour l'utilisateur.")

