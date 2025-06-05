# app.py
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import base64
import os
import json
import time
import random
# Importer la bibliothèque Twilio (assurez-vous de l'installer: pip install twilio)
from twilio.rest import Client
import uuid # Pour générer des tokens uniques

app = Flask(__name__)
# Clé secrète pour sécuriser les sessions Flask (même si non utilisées ici, bonne pratique)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'une_cle_tres_secrete_par_defaut_unique') # À changer!

# --- Configuration Twilio ---
# Utilisez des variables d'environnement pour les identifiants Twilio.
# Remplacez par vos vrais identifiants ou configurez les variables d'environnement.
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', "VOTRE_SID_ICI_SI_PAS_D_ENV")
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', "VOTRE_AUTH_TOKEN_ICI_SI_PAS_D_ENV")
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER', "VOTRE_NUMERO_TWILIO_ICI_SI_PAS_D_ENV")

twilio_client = None
# AJOUTÉ: Vérification plus explicite des identifiants Twilio
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER and \
   "VOTRE_SID_ICI" not in TWILIO_ACCOUNT_SID and \
   "VOTRE_AUTH_TOKEN_ICI" not in TWILIO_AUTH_TOKEN and \
   "VOTRE_NUMERO_TWILIO_ICI" not in TWILIO_PHONE_NUMBER:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        print("Client Twilio initialisé avec succès.")
    except Exception as e:
        print(f"ERREUR lors de l'initialisation du client Twilio: {e}")
        twilio_client = None
else:
    print("AVERTISSEMENT: Client Twilio non initialisé. Vérifiez les variables d'environnement TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER.")

def send_sms(to_phone_number, message_body):
    """Envoie un SMS via Twilio."""
    print(f"Tentative d'envoi de SMS à : {to_phone_number} avec message : '{message_body}'") # AJOUTÉ: Log
    if twilio_client and TWILIO_PHONE_NUMBER and to_phone_number:
        # AJOUTÉ: S'assurer que le numéro de téléphone commence par '+'
        if not to_phone_number.startswith('+'):
            print(f"AVERTISSEMENT: Le numéro de téléphone du destinataire '{to_phone_number}' ne commence pas par '+'. Tentative d'ajout du préfixe international (peut échouer).")
            # Ceci est une supposition et pourrait ne pas être correct pour tous les pays.
            # Idéalement, le numéro doit être stocké au format E.164 (+countrycodeXXXXXXXXXX)
            # Pour la France, si c'est 06, on pourrait essayer +336, mais c'est risqué.
            # Il est préférable que l'utilisateur entre le numéro au bon format.
            # to_phone_number = "+XX" + to_phone_number.lstrip('0') # Remplacer XX par le code pays par défaut
        
        try:
            message = twilio_client.messages.create(
                to=to_phone_number,
                from_=TWILIO_PHONE_NUMBER,
                body=message_body
            )
            print(f"SMS envoyé avec succès à {to_phone_number}. SID du message: {message.sid}")
            return True
        except Exception as e:
            print(f"ERREUR lors de l'envoi du SMS à {to_phone_number} via Twilio: {e}")
            return False
    else:
        if not twilio_client:
            print("Échec de l'envoi du SMS: Client Twilio non initialisé.")
        if not TWILIO_PHONE_NUMBER:
            print("Échec de l'envoi du SMS: Numéro de téléphone Twilio (expéditeur) manquant.")
        if not to_phone_number:
            print("Échec de l'envoi du SMS: Numéro de téléphone du destinataire manquant.")
        return False

# --- Configuration du fichier JSON ---
JSON_FILE_PATH = 'users.json' 

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
                     if 'totp_secret' not in user_data: # Devrait être là pour la logique TOTP
                         user_data['totp_secret'] = None 
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

auth_states = {}
STATE_TIMEOUT = 300 
device_last_seen = {}
DEVICE_TIMEOUT = 20 # L'appareil doit poller plus fréquemment que ça (ex: toutes les 5-10s)

def cleanup_expired_states():
    current_time = time.time()
    expired_users = [username for username, data in list(auth_states.items()) if current_time > data.get('timestamp', 0) + STATE_TIMEOUT]
    for username in expired_users:
        print(f"Nettoyage de l'état expiré pour {username} (statut: {auth_states.get(username, {}).get('status')})")
        if username in auth_states: del auth_states[username]
        if username in device_last_seen: del device_last_seen[username]

def is_device_online(username, device_type):
    current_time = time.time()
    if username in device_last_seen and device_type in device_last_seen[username]:
        last_seen_time = device_last_seen[username][device_type]
        #print(f"DEBUG: Appareil {device_type} pour {username} vu pour la dernière fois à {last_seen_time}. Actuel: {current_time}. Diff: {current_time - last_seen_time}")
        return current_time < last_seen_time + DEVICE_TIMEOUT
    #print(f"DEBUG: Appareil {device_type} pour {username} non vu récemment ou pas dans device_last_seen.")
    return False

# --- Routes UI ---
@app.route('/')
def index():
    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Connexion Compte Cloud</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:400px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1,h2{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-primary{background-color:#007bff;border:none;transition:background-color 0.2s;}.btn-primary:hover{background-color:#0056b3;}.alert{margin-top:20px;}</style></head>
        <body><div class="container"><h1>Accès Cloud</h1><h2>Connexion</h2>
        <form id="loginForm" action="/login" method="post"><div class="mb-3"><label for="username" class="form-label">Nom d'utilisateur:</label><input type="text" class="form-control" id="username" name="username" required></div>
        <div class="mb-3"><label for="password" class="form-label">Mot de passe:</label><input type="password" class="form-control" id="password" name="password" required></div>
        <button type="submit" class="btn btn-primary w-100">Se Connecter</button></form>
        <p class="text-center mt-3"><a href="/register">Nouveau? S'inscrire ici.</a></p>
        <div id="login-status" class="alert d-none" role="alert"></div></div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.getElementById('loginForm').addEventListener('submit', async function(event) {
                event.preventDefault(); const form = event.target; const formData = new FormData(form);
                const response = await fetch(form.action, { method: form.method, body: formData });
                const result = await response.json(); const statusDiv = document.getElementById('login-status');
                statusDiv.innerHTML = result.message; statusDiv.className = 'alert'; /* Reset classes */
                if (result.status === 'fail') statusDiv.classList.add('alert-danger');
                else if (result.status === '2fa_required') statusDiv.classList.add('alert-info');
                else statusDiv.classList.add('alert-warning');
                statusDiv.classList.remove('d-none');
                if (result.status === '2fa_required' && result.redirect_url) {
                    setTimeout(() => { window.location.href = result.redirect_url; }, 2500); // Délai légèrement augmenté
                }
            });
        </script></body></html>
    ''')

@app.route('/register')
def register_page():
    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Inscription</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:500px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-success{background-color:#28a745;border:none;}.btn-success:hover{background-color:#1e7e34;}.alert{margin-top:20px;} .secret-display{font-weight:bold; color: #dc3545; word-break:break-all;}</style></head>
        <body><div class="container"><h1>Inscription</h1>
        <form id="registerForm" action="/register" method="post">
            <div class="mb-3"><label for="username" class="form-label">Nom d'utilisateur:</label><input type="text" class="form-control" id="username" name="username" required></div>
            <div class="mb-3"><label for="password" class="form-label">Mot de passe:</label><input type="password" class="form-control" id="password" name="password" required></div>
            <div class="mb-3"><label for="phone_number" class="form-label">Numéro de téléphone (format E.164, ex: +33612345678):</label><input type="tel" class="form-control" id="phone_number" name="phone_number" placeholder="+33612345678" required><small class="form-text text-muted">Requis pour recevoir les codes 2FA par SMS.</small></div>
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
            document.getElementById('registerForm').addEventListener('submit', async function(event) {
                event.preventDefault(); const form = event.target; const formData = new FormData(form);
                const response = await fetch(form.action, { method: form.method, body: formData });
                const result = await response.json(); const statusDiv = document.getElementById('register-status');
                // MODIFIÉ: Afficher le message complet, y compris le secret TOTP si présent.
                let messageHtml = result.message;
                if (result.totp_secret) { // Si le secret est dans la réponse JSON
                    messageHtml += "<br><strong>IMPORTANT: Votre clé secrète TOTP à configurer sur votre appareil est : <span class=\\"secret-display\\">" + result.totp_secret + "</span></strong><br>Notez-la précieusement !";
                }
                statusDiv.innerHTML = messageHtml; // Utiliser innerHTML pour le formatage
                statusDiv.className = 'alert'; 
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
        return jsonify({"message": "Nom d'utilisateur, mot de passe et numéro de téléphone (au format +XX) sont requis."}), 400
    if not phone_number.startswith('+') or not phone_number[1:].isdigit() or len(phone_number) < 10 : # Validation basique du format E.164
        return jsonify({"message": "Format du numéro de téléphone invalide. Utilisez le format E.164 (ex: +33612345678)."}), 400
    if not enabled_devices:
         return jsonify({"message": "Veuillez sélectionner au moins un dispositif 2FA."}), 400
    if username in users:
        return jsonify({"message": "Ce nom d'utilisateur existe déjà."}), 409

    totp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    users[username] = {
        'password_hash': generate_password_hash(password),
        'totp_secret': totp_secret,
        'enabled_devices': enabled_devices,
        'phone_number': phone_number
    }
    save_users(users)
    print(f"Utilisateur '{username}' enregistré. Dispositifs: {enabled_devices}. Numéro: {phone_number}. Secret TOTP (pour l'appareil): {totp_secret}")
    # MODIFIÉ: Retourner le secret dans le JSON pour que le JS puisse l'afficher
    return jsonify({
        "message": f"Utilisateur '{username}' enregistré avec succès.",
        "totp_secret": totp_secret, # AJOUTÉ: Envoyer le secret au client
        "devices_info": f"Configurez vos appareils ({', '.join(enabled_devices)}) avec ce secret."
    }), 201

@app.route('/login', methods=['POST'])
def login():
    cleanup_expired_states()
    username = request.form.get('username')
    password = request.form.get('password')
    user = users.get(username)

    print(f"DEBUG: Tentative de connexion pour l'utilisateur: {username}")
    if not user or not check_password_hash(user['password_hash'], password):
        print(f"Échec de connexion (identifiants invalides) pour '{username}'.")
        if user and user.get('phone_number'):
             send_sms(user['phone_number'], f"Alerte: Tentative de connexion échouée (identifiants) pour votre compte {username}.")
        if username: auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
        return jsonify({"status": "fail", "message": "Nom d'utilisateur ou mot de passe invalide."}), 401

    print(f"Mot de passe correct pour '{username}'. 2FA requise.")
    enabled_devices = user.get('enabled_devices', [])
    if not enabled_devices:
         print(f"Aucun appareil 2FA activé pour '{username}'.")
         if user.get('phone_number'): send_sms(user['phone_number'], f"Échec connexion: Aucun appareil 2FA activé pour {username}.")
         auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
         return jsonify({"status": "fail", "message": "Aucun appareil 2FA configuré pour ce compte."}), 400

    online_devices = [device for device in enabled_devices if is_device_online(username, device)]
    print(f"Appareils activés pour '{username}': {enabled_devices}. Appareils en ligne: {online_devices}")

    if not online_devices:
         message = f"Aucun de vos appareils 2FA ({', '.join(enabled_devices)}) n'est actuellement en ligne. Veuillez vérifier qu'ils sont connectés et interrogent le serveur."
         print(f"Pour '{username}': {message}")
         if user.get('phone_number'): send_sms(user['phone_number'], f"Échec connexion: {message}")
         auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
         return jsonify({"status": "fail", "message": message}), 400

    chosen_device = random.choice(online_devices)
    print(f"Appareil 2FA choisi pour '{username}': {chosen_device}")
    browser_token = str(uuid.uuid4())
    auth_states[username] = {
        'status': 'awaiting_device_totp', 
        'device': chosen_device,
        'browser_token': browser_token,
        'received_totp': None,
        'timestamp': time.time()
    }
    print(f"État pour '{username}' mis à jour: awaiting_device_totp (appareil attendu: {chosen_device})")
    return jsonify({
        "status": "2fa_required",
        "message": f"Mot de passe correct. Le serveur attend que votre appareil '{chosen_device}' envoie un code TOTP. Vous recevrez ensuite un SMS.",
        "redirect_url": url_for('verify_totp_page', token=browser_token, _external=True)
    }), 200

@app.route('/verify_totp_page')
def verify_totp_page():
    browser_token = request.args.get('token')
    username = None
    for user_iter, state_data_iter in auth_states.items():
        if state_data_iter.get('browser_token') == browser_token:
            username = user_iter
            break
    if not username or username not in auth_states or time.time() > auth_states[username].get('timestamp', 0) + STATE_TIMEOUT:
        if username and username in auth_states: del auth_states[username]
        return "Requête invalide ou expirée. Veuillez recommencer la connexion.", 400

    state_data = auth_states[username]
    current_status = state_data['status']
    device_in_charge = state_data.get('device', 'sélectionné')
    page_message = f"Attente du code TOTP de votre appareil '{device_in_charge}'..."
    
    if current_status == 'awaiting_user_totp_entry':
        page_message = f"Code TOTP reçu de l'appareil '{device_in_charge}'. Veuillez saisir ce code (reçu par SMS) ci-dessous."
    elif current_status == 'awaiting_device_totp':
         page_message = f"Le serveur attend que votre appareil '{device_in_charge}' génère et envoie un code TOTP. Veuillez patienter pour le SMS."

    return render_template_string('''
        <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vérification TOTP 2FA</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>body{background-color:#f8f9fa;font-family:sans-serif;}.container{max-width:450px;margin-top:50px;padding:25px;background-color:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);}h1{text-align:center;margin-bottom:25px;color:#333;}.form-label{font-weight:bold;}.btn-primary{background-color:#007bff;border:none;}.btn-primary:hover{background-color:#0056b3;}.alert{margin-top:20px;}</style></head>
        <body><div class="container"><h1>Vérification 2FA</h1>
        <p class="text-center" id="status-message">{{ page_message_param }}</p>
        <form id="verifyOtpForm" action="/verify_totp" method="post">
            <input type="hidden" name="token" value="{{ browser_token_param }}">
            <div class="mb-3"><label for="device_name" class="form-label">Code provenant de l'appareil :</label><input type="text" class="form-control" id="device_name" name="device_name" value="{{ device_name_param }}" readonly required><small class="form-text text-muted">Cet appareil a été sollicité pour le code.</small></div>
            <div class="mb-3"><label for="totp_code" class="form-label">Code TOTP reçu par SMS:</label><input type="text" class="form-control" id="totp_code" name="totp_code" pattern="[0-9]{6}" title="Le code TOTP doit contenir 6 chiffres." required maxlength="6"></div>
            <button type="submit" class="btn btn-primary w-100">Vérifier le Code</button>
        </form>
        <div id="verification-status" class="alert d-none" role="alert"></div></div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.getElementById('verifyOtpForm').addEventListener('submit', async function(event) {
                event.preventDefault(); const form = event.target; const formData = new FormData(form);
                const response = await fetch(form.action, { method: form.method, body: formData });
                const result = await response.json(); const statusDiv = document.getElementById('verification-status');
                statusDiv.innerHTML = result.message; statusDiv.className = 'alert';
                if (result.status === 'success') {
                    statusDiv.classList.add('alert-success');
                    if(result.redirect_url) setTimeout(() => { window.location.href = result.redirect_url; }, 2000);
                } else { statusDiv.classList.add('alert-danger'); }
                statusDiv.classList.remove('d-none');
            });
        </script></body></html>
    ''', browser_token_param=browser_token, page_message_param=page_message, device_name_param=device_in_charge)

@app.route('/verify_totp', methods=['POST'])
def verify_totp():
    cleanup_expired_states()
    browser_token = request.form.get('token')
    # device_name_user_input = request.form.get('device_name') # Est readonly, mais on peut le récupérer
    totp_code_user_input = request.form.get('totp_code')

    username = None
    for user_iter, state_data_iter in auth_states.items():
        if state_data_iter.get('browser_token') == browser_token:
            username = user_iter
            break
    if not username or username not in auth_states or time.time() > auth_states[username].get('timestamp', 0) + STATE_TIMEOUT:
        if username and username in auth_states: del auth_states[username]
        return jsonify({"status": "fail", "message": "Session de vérification expirée ou invalide. Recommencez."}), 400

    state_data = auth_states[username]
    received_device_totp = state_data.get('received_totp')
    # chosen_device_by_server = state_data.get('device') # L'appareil que le serveur avait choisi

    print(f"DEBUG (verify_totp pour '{username}'): Code saisi par utilisateur: {totp_code_user_input}, Code reçu de l'appareil: {received_device_totp}, État actuel: {state_data['status']}")

    if state_data['status'] != 'awaiting_user_totp_entry' or not received_device_totp:
         print(f"Échec vérification TOTP pour '{username}': Le serveur n'attendait pas la saisie utilisateur ou n'a pas reçu de TOTP de l'appareil.")
         return jsonify({"status": "fail", "message": "Le code TOTP de votre appareil n'a pas encore été reçu par le serveur, ou l'état est incorrect. Attendez le SMS et réessayez."}), 400

    if totp_code_user_input == received_device_totp: # Comparaison directe du code
        print(f"Vérification TOTP réussie pour '{username}'.")
        auth_states[username]['status'] = 'success'
        auth_states[username]['timestamp'] = time.time()
        user_data = users.get(username)
        if user_data and user_data.get('phone_number'):
             send_sms(user_data['phone_number'], f"Connexion réussie à votre compte cloud (via {state_data.get('device')}).")
        return jsonify({"status": "success", "message": "Vérification 2FA réussie! Redirection...", "redirect_url": url_for('cloud_space', _external=True)}), 200
    else:
        print(f"Échec vérification TOTP pour '{username}': Code saisi ('{totp_code_user_input}') invalide. Code attendu: '{received_device_totp}'.")
        user_data = users.get(username)
        if user_data and user_data.get('phone_number'):
             send_sms(user_data['phone_number'], f"Tentative de connexion échouée (code 2FA saisi invalide) pour le compte {username}.")
        return jsonify({"status": "fail", "message": "Code TOTP invalide."}), 401

# --- Endpoints pour Appareils IoT ---
@app.route('/submit_device_totp', methods=['POST'])
def submit_device_totp():
    cleanup_expired_states()
    data = request.get_json()
    if not data:
        print("ERREUR (submit_device_totp): Aucune donnée JSON reçue.")
        return jsonify({"status": "error", "message": "Requête JSON attendue"}), 400
        
    username = data.get('username')
    device_type = data.get('device_type')
    totp_code_from_device = data.get('totp')

    print(f"DEBUG (submit_device_totp): Reçu de l'appareil -> User: {username}, Device: {device_type}, TOTP: {totp_code_from_device}")

    if not username or not device_type or not totp_code_from_device:
        print(f"ERREUR (submit_device_totp): Données manquantes - User: {username}, Device: {device_type}, TOTP: {totp_code_from_device}")
        return jsonify({"status": "error", "message": "Données manquantes (username, device_type, totp)"}), 400

    state_data = auth_states.get(username)
    user_config = users.get(username)

    if not user_config:
        print(f"ERREUR (submit_device_totp): Utilisateur '{username}' non trouvé dans la base de données.")
        return jsonify({"status": "fail", "message": "Utilisateur inconnu"}), 400
        
    if not state_data:
        print(f"AVERTISSEMENT (submit_device_totp): Pas d'état d'authentification actif trouvé pour '{username}' lors de la soumission par {device_type}.")
        # Optionnel: Alerter l'utilisateur si son appareil soumet un code alors qu'aucune connexion n'est en cours
        if user_config.get('phone_number'):
            send_sms(user_config['phone_number'], f"Alerte: Votre appareil {device_type} a tenté de soumettre un code 2FA alors qu'aucune connexion n'était attendue pour {username}.")
        return jsonify({"status": "fail", "message": "Aucune tentative de connexion active pour cet utilisateur"}), 400


    if state_data.get('status') != 'awaiting_device_totp' or state_data.get('device') != device_type:
        print(f"ERREUR (submit_device_totp): Soumission TOTP non attendue pour '{username}' depuis {device_type}. État actuel: {state_data.get('status')}, Appareil attendu: {state_data.get('device')}.")
        if user_config.get('phone_number'):
            send_sms(user_config['phone_number'], f"Alerte: Soumission 2FA inattendue de {device_type} pour {username} (état serveur: {state_data.get('status')}).")
        return jsonify({"status": "fail", "message": "Soumission non attendue de cet appareil ou état incorrect"}), 400

    # Vérifier le TOTP soumis par l'appareil avec le secret de l'utilisateur
    totp_verifier = pyotp.TOTP(user_config['totp_secret'])
    if not totp_verifier.verify(totp_code_from_device): # Fenêtre de validité par défaut (actuel, précédent, suivant)
         print(f"ERREUR (submit_device_totp): Code TOTP '{totp_code_from_device}' de {device_type} pour '{username}' est INVALIDE (vérification serveur).")
         auth_states[username]['status'] = 'fail' # Marquer la tentative comme échouée
         auth_states[username]['timestamp'] = time.time()
         if user_config.get('phone_number'):
              send_sms(user_config['phone_number'], f"Échec connexion: Code 2FA invalide soumis par votre appareil {device_type} pour {username}.")
         return jsonify({"status": "fail", "message": "Code TOTP invalide fourni par l'appareil"}), 401
    
    print(f"Code TOTP '{totp_code_from_device}' de {device_type} pour '{username}' est VALIDE (vérification serveur).")
    auth_states[username]['received_totp'] = totp_code_from_device
    auth_states[username]['status'] = 'awaiting_user_totp_entry'
    auth_states[username]['timestamp'] = time.time()

    sms_message_body = f"Votre code de vérification pour le compte cloud (provenant de {device_type}): {totp_code_from_device}"
    print(f"Préparation pour envoyer SMS à {user_config.get('phone_number')} avec message: {sms_message_body}")
    
    if user_config.get('phone_number'):
        if send_sms(user_config['phone_number'], sms_message_body):
            print(f"SMS avec TOTP envoyé à '{username}'.")
        else:
            print(f"Échec de l'envoi du SMS avec TOTP à '{username}'.")
    else:
        print(f"Aucun numéro de téléphone pour '{username}', SMS non envoyé. Le code était: {totp_code_from_device}")

    return jsonify({"status": "success", "message": "TOTP reçu et validé par le serveur. SMS (potentiellement) envoyé."}), 200


@app.route('/check_auth_status', methods=['POST'])
def check_auth_status():
    cleanup_expired_states()
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Requête JSON attendue"}), 400

    username = data.get('username')
    device_type = data.get('device_type')

    if not username or not device_type:
        return jsonify({"status": "error", "message": "Champs 'username' et 'device_type' requis"}), 400

    if username not in device_last_seen: device_last_seen[username] = {}
    device_last_seen[username][device_type] = time.time()
    #print(f"DEBUG (check_auth_status): Appareil {device_type} pour {username} a fait un check-in.")

    state_data = auth_states.get(username)
    if state_data and time.time() < state_data.get('timestamp', 0) + STATE_TIMEOUT:
        status = state_data['status']
        response_data = {"status": status}
        if status == 'awaiting_device_totp' and state_data.get('device') == device_type:
             response_data['action'] = 'generate_and_submit_totp'
             response_data['message'] = f"Le serveur attend un TOTP de votre part ({device_type})."
             #print(f"DEBUG (check_auth_status): Demande de TOTP à {device_type} pour {username}.")
        elif status in ['success', 'fail']:
             response_data['action'] = 'stop_polling'
             response_data['message'] = f"Authentification terminée ({status})."
             #print(f"DEBUG (check_auth_status): Fin de polling pour {device_type} / {username}.")
        else: 
             response_data['action'] = 'wait'
             response_data['message'] = f"En attente (état: {status}). Pas d'action TOTP requise de l'appareil pour le moment."
        return jsonify(response_data), 200
    else:
        #print(f"DEBUG (check_auth_status): Aucun état actif pour {username} (demandé par {device_type}).")
        return jsonify({"status": "not_authenticated", "action": "wait", "message": "Aucun état d'authentification actif"}), 200

@app.route('/cloud_space')
def cloud_space():
    cleanup_expired_states()
    authenticated_user = None
    current_time = time.time()
    for user_iter, state_data_iter in list(auth_states.items()):
        if state_data_iter.get('status') == 'success' and current_time < state_data_iter.get('timestamp', 0) + STATE_TIMEOUT:
            authenticated_user = user_iter
            break
    if authenticated_user:
        return render_template_string(f'''
            <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Espace Cloud</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>body{{font-family:sans-serif; background-color:#e9ecef; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0;}}
            .container{{text-align:center; background-color:#fff; padding:40px; border-radius:10px; box-shadow:0 0 20px rgba(0,0,0,0.1);}}
            h1{{color:#007bff; margin-bottom:20px;}} p{{font-size:1.2em;}}
            .btn-logout{{background-color:#dc3545; color:white; margin-top:30px; padding:10px 20px;text-decoration:none;border-radius:5px;}}
            .btn-logout:hover{{background-color:#c82333;}}</style></head>
            <body><div class="container"><h1>Bienvenue, {authenticated_user}!</h1>
            <p>Votre espace cloud sécurisé.</p>
            <a href="/" class="btn btn-logout">Déconnexion</a>
            </div></body></html>
        ''')
    else:
        print("Accès à /cloud_space refusé: non authentifié ou session expirée.")
        return redirect(url_for('index'))

if __name__ == '__main__':
    print("Démarrage de l'application Flask (mode TOTP).")
    print("Assurez-vous que les variables d'environnement TWILIO sont configurées pour l'envoi de SMS.")
    # Pour tests locaux, Flask peut être lancé avec :
    # app.run(debug=True, host='0.0.0.0', port=5000) # ou un autre port si 5000 est pris
    # Sur Render, Gunicorn est généralement utilisé via un Procfile.
