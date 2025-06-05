# app.py
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session # Ajout de session
from werkzeug.security import generate_password_hash, check_password_hash
# import pyotp # Plus nécessaire pour ce flux spécifique
import base64
import os
import json
import time
import random
# Importer la bibliothèque Twilio (assurez-vous de l'installer: pip install twilio)
from twilio.rest import Client
import uuid # Pour générer des tokens uniques

app = Flask(__name__)
# Clé secrète pour sécuriser les sessions Flask
# Utilisez une variable d'environnement en production!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'une_cle_tres_secrete_par_defaut_a_changer')

# --- Configuration Twilio ---
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')

twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        print("Client Twilio initialisé.")
    except Exception as e:
        print(f"Erreur lors de l'initialisation du client Twilio: {e}")
else:
    print("Variables d'environnement Twilio manquantes. L'envoi de SMS sera désactivé.")

def send_sms(to_phone_number, message_body):
    if not twilio_client:
        print(f"Client Twilio non initialisé. Simulation d'envoi SMS à {to_phone_number}: {message_body}")
        # Pour le test sans Twilio configuré, on simule un succès
        return True
    if not to_phone_number:
        print("Numéro de téléphone destinataire manquant. SMS non envoyé.")
        return False
    try:
        message = twilio_client.messages.create(
            to=to_phone_number,
            from_=TWILIO_PHONE_NUMBER,
            body=message_body
        )
        print(f"SMS envoyé à {to_phone_number} (SID: {message.sid})")
        return True
    except Exception as e:
        print(f"Échec de l'envoi du SMS à {to_phone_number}: {e}")
        return False

# --- Configuration du fichier JSON ---
JSON_FILE_PATH = 'users.json'

def load_users():
    if os.path.exists(JSON_FILE_PATH):
        try:
            with open(JSON_FILE_PATH, 'r') as f:
                data = json.load(f)
                for user_data in data.values():
                    user_data.setdefault('enabled_devices', [])
                    user_data.setdefault('phone_number', None)
                    # totp_secret n'est plus utilisé dans ce flux
                    user_data.pop('totp_secret', None)
                return data
        except (json.JSONDecodeError, Exception) as e:
            print(f"Erreur lors du chargement de {JSON_FILE_PATH}: {e}. Utilisation d'un dictionnaire vide.")
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
# {username: {'status': '...', 'device_expected': '...', 'received_device_code': '...', 'sms_sent': bool, 'timestamp': '...'}}
# Status: 'password_correct', 'awaiting_device_code', 'awaiting_sms_verification', 'success', 'fail'
auth_states = {}
STATE_TIMEOUT = 300 # 5 minutes

def cleanup_expired_states():
    current_time = time.time()
    expired_users = [username for username, data in list(auth_states.items()) if current_time > data['timestamp'] + STATE_TIMEOUT]
    for username in expired_users:
        print(f"Nettoyage de l'état expiré pour {username}")
        if username in auth_states:
             del auth_states[username]

# --- Routes --- #

@app.route('/')
def index():
    # Page de login
    return render_template_string('''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style> body { background-color: #f8f9fa; } .container { max-width: 400px; margin-top: 50px; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); } </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">Connexion</h1>
        <form id="login-form" action="/login" method="post">
            <div class="mb-3">
                <label for="username" class="form-label">Nom d'utilisateur:</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Mot de passe:</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Se Connecter</button>
        </form>
        <p class="text-center mt-3">Nouveau? <a href="/register">S'inscrire ici</a>.</p>
        <div id="login-status" class="alert d-none mt-3" role="alert"></div>
    </div>
    <script>
        document.getElementById('login-form').addEventListener('submit', async function(event) {
            event.preventDefault();
            const form = event.target;
            const formData = new FormData(form);
            const statusDiv = document.getElementById('login-status');
            statusDiv.classList.add('d-none'); // Cacher l'ancien statut

            try {
                const response = await fetch(form.action, {
                    method: form.method,
                    body: formData
                });
                const result = await response.json();

                statusDiv.textContent = result.message;
                statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger', 'alert-info');

                if (result.status === 'success') {
                    statusDiv.classList.add('alert-success');
                    // Redirection vers une page de succès ou tableau de bord
                    // window.location.href = '/dashboard'; // Exemple
                } else if (result.status === 'awaiting_device_code') {
                    statusDiv.classList.add('alert-info');
                    // Pas de redirection ici, l'utilisateur attend l'action de l'appareil
                    // On pourrait ajouter un indicateur d'attente
                } else if (result.status === 'redirect_to_sms_verify') {
                     statusDiv.classList.add('alert-info');
                     // Rediriger vers la page de vérification SMS après un court délai
                     setTimeout(() => {
                         window.location.href = result.redirect_url;
                     }, 1500);
                } else {
                    statusDiv.classList.add('alert-danger');
                }
            } catch (error) {
                console.error('Erreur lors de la connexion:', error);
                statusDiv.textContent = 'Une erreur est survenue.';
                statusDiv.classList.remove('d-none');
                statusDiv.classList.add('alert-danger');
            }
        });
    </script>
</body>
</html>
    ''')

@app.route('/register')
def register_page():
    # Page d'inscription
    return render_template_string('''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inscription</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style> body { background-color: #f8f9fa; } .container { max-width: 500px; margin-top: 50px; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); } </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">Inscription</h1>
        <form id="register-form" action="/register" method="post">
            <div class="mb-3">
                <label for="username" class="form-label">Nom d'utilisateur:</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Mot de passe:</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <div class="mb-3">
                <label for="phone_number" class="form-label">Numéro de téléphone (format +33xxxxxxxxx):</label>
                <input type="tel" class="form-control" id="phone_number" name="phone_number" required pattern="\+[0-9]{10,15}">
                <small class="form-text text-muted">Requis pour recevoir le code de vérification par SMS.</small>
            </div>
            <div class="mb-3">
                <label class="form-label">Choisissez vos dispositifs 2FA (au moins un):</label><br>
                <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" id="device_pi" name="device" value="pi">
                    <label class="form-check-label" for="device_pi">Raspberry Pi</label>
                </div>
                <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" id="device_esp32" name="device" value="esp32">
                    <label class="form-check-label" for="device_esp32">ESP32</label>
                </div>
            </div>
            <button type="submit" class="btn btn-success w-100">S'inscrire</button>
        </form>
        <p class="text-center mt-3">Déjà inscrit? <a href="/">Se connecter</a>.</p>
        <div id="register-status" class="alert d-none mt-3" role="alert"></div>
    </div>
    <script>
        document.getElementById('register-form').addEventListener('submit', async function(event) {
            event.preventDefault();
            const form = event.target;
            const formData = new FormData(form);
            const statusDiv = document.getElementById('register-status');
            statusDiv.classList.add('d-none');

            try {
                const response = await fetch(form.action, {
                    method: form.method,
                    body: formData
                });
                const result = await response.json();
                statusDiv.textContent = result.message;
                statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger');
                if (response.ok) {
                    statusDiv.classList.add('alert-success');
                    form.reset(); // Vider le formulaire en cas de succès
                } else {
                    statusDiv.classList.add('alert-danger');
                }
            } catch (error) {
                console.error('Erreur lors de l'inscription:', error);
                statusDiv.textContent = 'Une erreur est survenue.';
                statusDiv.classList.remove('d-none');
                statusDiv.classList.add('alert-danger');
            }
        });
    </script>
</body>
</html>
    ''')

@app.route('/register', methods=['POST'])
def register():
    global users
    username = request.form.get('username')
    password = request.form.get('password')
    phone_number = request.form.get('phone_number')
    enabled_devices = request.form.getlist('device') # Récupère la liste des appareils cochés

    if not username or not password or not phone_number:
        return jsonify({'message': 'Nom d'utilisateur, mot de passe et numéro de téléphone requis.'}), 400

    # Validation simple du format du numéro (commence par + et suivi de chiffres)
    if not phone_number.startswith('+') or not phone_number[1:].isdigit():
         return jsonify({'message': 'Format du numéro de téléphone invalide (doit commencer par + suivi de chiffres).'}), 400

    if not enabled_devices:
        return jsonify({'message': 'Veuillez sélectionner au moins un dispositif 2FA.'}), 400

    if username in users:
        return jsonify({'message': 'Nom d'utilisateur déjà pris.'}), 409

    hashed_password = generate_password_hash(password)
    users[username] = {
        'password_hash': hashed_password,
        'phone_number': phone_number,
        'enabled_devices': enabled_devices
    }
    save_users(users)
    print(f"Utilisateur {username} enregistré avec les appareils: {enabled_devices}")
    return jsonify({'message': f'Utilisateur {username} enregistré avec succès.'}), 201

@app.route('/login', methods=['POST'])
def login():
    global users, auth_states
    cleanup_expired_states()

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Nom d'utilisateur et mot de passe requis.'}), 400

    user_data = users.get(username)
    if not user_data or not check_password_hash(user_data['password_hash'], password):
        return jsonify({'status': 'fail', 'message': 'Identifiants incorrects.'}), 401

    # Identifiants corrects, passer à l'étape 2FA
    enabled_devices = user_data.get('enabled_devices', [])
    if not enabled_devices:
         # Cas où l'utilisateur est enregistré mais sans appareil (ne devrait pas arriver avec la validation à l'inscription)
         print(f"Avertissement: Utilisateur {username} sans appareil 2FA configuré.")
         return jsonify({'status': 'fail', 'message': 'Aucun appareil 2FA configuré pour ce compte.'}), 403

    # Pour cet exemple, on prend le premier appareil activé (ex: 'esp32')
    # Une logique plus complexe pourrait demander à l'utilisateur de choisir si plusieurs sont actifs
    device_to_use = enabled_devices[0]

    # Générer un token unique pour cette tentative de connexion
    # browser_token = str(uuid.uuid4())

    # Stocker l'état d'authentification
    auth_states[username] = {
        'status': 'awaiting_device_code',
        'device_expected': device_to_use,
        'received_device_code': None,
        'sms_sent': False,
        # 'browser_token': browser_token, # On utilisera la session Flask plutôt
        'timestamp': time.time()
    }

    # Stocker le username dans la session pour le retrouver plus tard
    session['username'] = username
    session['login_attempt_time'] = time.time() # Pour vérifier la fraîcheur de la tentative

    print(f"Login étape 1 réussie pour {username}. En attente du code de l'appareil {device_to_use}.")
    # Informer l'utilisateur qu'il doit attendre le code de son appareil
    return jsonify({
        'status': 'awaiting_device_code',
        'message': f'Identifiants corrects. Veuillez attendre le code de vérification de votre appareil ({device_to_use})...',
        # 'browser_token': browser_token # Pas besoin si on utilise la session
    }), 200

# NOUVELLE ROUTE pour recevoir le code de l'appareil (ESP32/Pi)
@app.route('/submit_device_code', methods=['POST'])
def submit_device_code():
    global auth_states, users
    cleanup_expired_states()

    data = request.get_json()
    if not data:
        return jsonify({'message': 'Requête invalide (JSON attendu).'}), 400

    username = data.get('username')
    device_type = data.get('device_type')
    code = data.get('code')

    if not username or not device_type or not code:
        return jsonify({'message': 'Données manquantes (username, device_type, code).'}), 400

    print(f"Code reçu de l'appareil {device_type} pour l'utilisateur {username}: {code}")

    # Vérifier si une tentative de connexion est en cours pour cet utilisateur
    if username not in auth_states:
        print(f"Aucune tentative de connexion active trouvée pour {username}.")
        return jsonify({'message': 'Aucune tentative de connexion active.'}), 404

    current_state = auth_states[username]

    # Vérifier si on attend bien un code de cet appareil
    if current_state['status'] != 'awaiting_device_code':
        print(f"État inattendu ({current_state['status']}) pour {username} lors de la réception du code appareil.")
        return jsonify({'message': 'État de connexion inattendu.'}), 409 # Conflict

    if current_state['device_expected'] != device_type:
        print(f"Appareil inattendu ({device_type}) pour {username}. Attendu: {current_state['device_expected']}.")
        return jsonify({'message': 'Type d'appareil incorrect.'}), 400

    # Stocker le code reçu et mettre à jour l'état
    current_state['received_device_code'] = str(code) # S'assurer que c'est une chaîne
    current_state['status'] = 'awaiting_sms_verification'
    current_state['timestamp'] = time.time() # Rafraîchir le timestamp

    # Récupérer le numéro de téléphone de l'utilisateur
    user_data = users.get(username)
    if not user_data or not user_data.get('phone_number'):
        print(f"Numéro de téléphone introuvable pour {username}. Impossible d'envoyer le SMS.")
        # Annuler l'état car on ne peut pas continuer
        del auth_states[username]
        return jsonify({'message': 'Erreur interne: Numéro de téléphone manquant.'}), 500

    phone_number = user_data['phone_number']
    sms_message = f"Votre code de vérification est : {code}"

    # Envoyer le SMS
    sms_sent_successfully = send_sms(phone_number, sms_message)

    if sms_sent_successfully:
        current_state['sms_sent'] = True
        print(f"SMS envoyé à {username} ({phone_number}). En attente de vérification.")
        # Le serveur a fait sa part, l'ESP32 peut considérer que c'est OK.
        # Le client web (navigateur) sera redirigé via une autre requête (check_status)
        return jsonify({'message': 'Code reçu et SMS envoyé.'}), 200
    else:
        print(f"Échec de l'envoi du SMS à {username}. Annulation de la tentative.")
        # Annuler l'état car le SMS n'a pas pu être envoyé
        del auth_states[username]
        return jsonify({'message': 'Échec de l'envoi du SMS.'}), 500

# NOUVELLE ROUTE pour vérifier périodiquement l'état après /login
@app.route('/check_login_status')
def check_login_status():
    cleanup_expired_states()
    username = session.get('username')
    login_attempt_time = session.get('login_attempt_time')

    if not username or not login_attempt_time:
        return jsonify({'status': 'fail', 'message': 'Session invalide ou expirée.'}), 401

    # Vérifier si la tentative de session est récente (évite réutilisation)
    if time.time() > login_attempt_time + STATE_TIMEOUT:
         session.pop('username', None)
         session.pop('login_attempt_time', None)
         return jsonify({'status': 'fail', 'message': 'Tentative de connexion expirée.'}), 401

    if username not in auth_states:
        # L'état a peut-être expiré ou a été complété/annulé
        return jsonify({'status': 'fail', 'message': 'État de connexion introuvable.'}), 404

    current_state = auth_states[username]

    if current_state['status'] == 'awaiting_sms_verification' and current_state['sms_sent']:
        # Le code a été reçu, le SMS envoyé, on peut rediriger vers la saisie SMS
        print(f"Statut pour {username} est {current_state['status']}. Préparation de la redirection vers la vérification SMS.")
        redirect_url = url_for('verify_sms_page') # Utilise la session, pas besoin de passer username/token
        return jsonify({
            'status': 'redirect_to_sms_verify',
            'message': 'Code reçu de l'appareil et SMS envoyé. Redirection vers la vérification...',
            'redirect_url': redirect_url
        }), 200
    elif current_state['status'] == 'awaiting_device_code':
        # Toujours en attente du code de l'appareil
        return jsonify({'status': 'awaiting_device_code', 'message': 'En attente du code de l'appareil...'}), 202 # Accepted
    else:
        # État inattendu ou échec
        return jsonify({'status': 'fail', 'message': f'État inattendu: {current_state['status']}'}), 409

# NOUVELLE ROUTE pour la page de saisie du code SMS
@app.route('/verify_sms', methods=['GET'])
def verify_sms_page():
    username = session.get('username')
    if not username or username not in auth_states or auth_states[username]['status'] != 'awaiting_sms_verification':
        # Rediriger vers login si l'état n'est pas correct
        return redirect(url_for('index'))

    # Afficher la page de saisie du code
    return render_template_string('''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérification SMS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style> body { background-color: #f8f9fa; } .container { max-width: 400px; margin-top: 50px; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); } </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">Vérification 2FA</h1>
        <p class="text-center">Un code a été envoyé par SMS au numéro associé à votre compte.</p>
        <form id="verify-form" action="/verify_sms" method="post">
            <div class="mb-3">
                <label for="sms_code" class="form-label">Code reçu par SMS:</label>
                <input type="text" class="form-control" id="sms_code" name="sms_code" required pattern="[0-9]{6}" inputmode="numeric" maxlength="6">
            </div>
            <button type="submit" class="btn btn-primary w-100">Vérifier</button>
        </form>
        <div id="verify-status" class="alert d-none mt-3" role="alert"></div>
    </div>
    <script>
        document.getElementById('verify-form').addEventListener('submit', async function(event) {
            event.preventDefault();
            const form = event.target;
            const formData = new FormData(form);
            const statusDiv = document.getElementById('verify-status');
            statusDiv.classList.add('d-none');

            try {
                const response = await fetch(form.action, {
                    method: form.method,
                    body: formData
                });
                const result = await response.json();
                statusDiv.textContent = result.message;
                statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger');

                if (result.status === 'success') {
                    statusDiv.classList.add('alert-success');
                    // Redirection vers le tableau de bord ou page d'accueil après succès
                    setTimeout(() => { window.location.href = '/success'; }, 1000);
                } else {
                    statusDiv.classList.add('alert-danger');
                }
            } catch (error) {
                console.error('Erreur lors de la vérification SMS:', error);
                statusDiv.textContent = 'Une erreur est survenue.';
                statusDiv.classList.remove('d-none');
                statusDiv.classList.add('alert-danger');
            }
        });
    </script>
</body>
</html>
    ''')

# NOUVELLE ROUTE pour traiter la soumission du code SMS
@app.route('/verify_sms', methods=['POST'])
def verify_sms_code():
    global auth_states
    cleanup_expired_states()

    username = session.get('username')
    login_attempt_time = session.get('login_attempt_time')
    sms_code_entered = request.form.get('sms_code')

    if not username or not login_attempt_time:
        return jsonify({'status': 'fail', 'message': 'Session invalide ou expirée.'}), 401

    # Vérifier fraîcheur
    if time.time() > login_attempt_time + STATE_TIMEOUT:
         session.pop('username', None)
         session.pop('login_attempt_time', None)
         if username in auth_states: del auth_states[username]
         return jsonify({'status': 'fail', 'message': 'Tentative de connexion expirée.'}), 401

    if not sms_code_entered:
        return jsonify({'status': 'fail', 'message': 'Code SMS requis.'}), 400

    if username not in auth_states or auth_states[username]['status'] != 'awaiting_sms_verification':
        return jsonify({'status': 'fail', 'message': 'État de vérification invalide.'}), 409

    current_state = auth_states[username]
    expected_code = current_state.get('received_device_code')

    if not expected_code:
        # Ne devrait pas arriver si l'état est correct
        print(f"Erreur: Code attendu manquant pour {username} dans l'état {current_state['status']}")
        del auth_states[username] # Nettoyer l'état incohérent
        session.pop('username', None)
        session.pop('login_attempt_time', None)
        return jsonify({'status': 'fail', 'message': 'Erreur interne du serveur.'}), 500

    if sms_code_entered == expected_code:
        print(f"Vérification SMS réussie pour {username}.")
        # Nettoyer l'état d'authentification temporaire
        del auth_states[username]
        # Marquer la session comme authentifiée (pourrait être utilisé par d'autres routes)
        session['authenticated'] = True
        session['auth_time'] = time.time()
        # Ne pas supprimer username/login_attempt_time tout de suite, peut être utile
        return jsonify({'status': 'success', 'message': 'Vérification réussie! Connexion établie.'}), 200
    else:
        print(f"Échec de la vérification SMS pour {username}. Attendu: {expected_code}, Reçu: {sms_code_entered}")
        # Ne pas supprimer l'état tout de suite, l'utilisateur pourrait réessayer (ajouter un compteur de tentatives?)
        # Pour l'instant, simple échec
        # Optionnel: Invalider la tentative après X échecs
        return jsonify({'status': 'fail', 'message': 'Code SMS incorrect.'}), 401

# Page de succès simple
@app.route('/success')
def success_page():
    username = session.get('username')
    if not session.get('authenticated'):
        return redirect(url_for('index'))

    # Nettoyer les infos temporaires de la session si on ne les utilise plus
    # session.pop('login_attempt_time', None)

    return render_template_string('''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Succès</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-success" role="alert">
            <h4 class="alert-heading">Connexion réussie!</h4>
            <p>Bienvenue, {{ username }}!</p>
            <hr>
            <p class="mb-0">Vous êtes maintenant connecté.</p>
        </div>
        <a href="/logout" class="btn btn-secondary">Se déconnecter</a>
    </div>
</body>
</html>
    ''', username=username)

@app.route('/logout')
def logout():
    # Nettoyer la session
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Utiliser '0.0.0.0' pour être accessible depuis l'extérieur du conteneur/VM
    # Le port 5000 est souvent utilisé par défaut pour Flask
    app.run(host='0.0.0.0', port=5000, debug=True) # debug=True pour le développement
