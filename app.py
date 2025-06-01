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
# Utilisez une variable d'environnement en production! Pour test local rapide:
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'une_cle_tres_secrete_par_defaut') # À changer!

# --- Configuration Twilio ---
# Utilisez des variables d'environnement pour les identifiants Twilio sur Render
# Pour test local rapide, vous pouvez les mettre ici (PAS EN PRODUCTION!)
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID') # Remplacez par votre SID
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN') # Remplacez par votre Auth Token
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER') # Remplacez par votre numéro Twilio

# Initialiser le client Twilio (sera None si les variables d'env ne sont pas définies)
twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        print("Client Twilio initialisé.")
    except Exception as e:
        print(f"Erreur lors de l'initialisation du client Twilio: {e}")
        twilio_client = None # S'assurer qu'il est None en cas d'erreur

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
        print("Client Twilio non configuré, numéro Twilio manquant ou numéro destinataire manquant. SMS non envoyé.")
        return False

# --- Configuration du fichier JSON ---
JSON_FILE_PATH = 'users.json' # Nom du fichier pour stocker les utilisateurs

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
                     if 'totp_secret' not in user_data:
                         user_data['totp_secret'] = None # Devrait toujours être là après inscription, mais sécurité
                return data
        except json.JSONDecodeError:
            # Gérer le cas où le fichier JSON est vide ou corrompu
            return {}
        except Exception as e:
             print(f"Erreur lors du chargement de users.json: {e}")
             return {}
    else:
        # Si le fichier n'existe pas, retourner un dictionnaire vide
        return {}

def save_users(users_data):
    """Sauvegarde les données des utilisateurs dans le fichier JSON."""
    try:
        with open(JSON_FILE_PATH, 'w') as f:
            json.dump(users_data, f, indent=4) # Utiliser indent pour une meilleure lisibilité
    except Exception as e:
        print(f"Erreur lors de la sauvegarde de users.json: {e}")


# Charger les utilisateurs au démarrage de l'application
# ATTENTION: Sur les services gratuits comme Render, ce fichier peut être réinitialisé
# à chaque redémarrage du service, entraînant la perte des utilisateurs enregistrés.
users = load_users()
print(f"Chargé {len(users)} utilisateurs depuis {JSON_FILE_PATH}")

# --- Gestion de l'état d'authentification temporaire ---
# Utilise un dictionnaire unique pour suivre l'état de chaque tentative de connexion par utilisateur
# {username: {'status': '...', 'device': '...', 'received_totp': '...', 'browser_token': '...', 'timestamp': '...'}}
# Status can be: 'password_correct', 'awaiting_device_totp', 'awaiting_user_totp_entry', 'success', 'fail'
auth_states = {}
STATE_TIMEOUT = 300 # Durée de validité d'un état en secondes (5 minutes)

# Stocke le dernier timestamp de polling pour chaque appareil d'un utilisateur
# {username: {device_type: timestamp}}
device_last_seen = {}
DEVICE_TIMEOUT = 10 # Temps en secondes après lequel un appareil est considéré hors ligne (doit être > POLLING_INTERVAL des clients)


def cleanup_expired_states():
    """Nettoie les états d'authentification temporaires expirés."""
    current_time = time.time()
    expired_users = [username for username, data in auth_states.items() if current_time > data['timestamp'] + STATE_TIMEOUT]
    for username in expired_users:
        print(f"Nettoyage de l'état expiré pour {username} (statut: {auth_states[username]['status']})")
        del auth_states[username]
        # Optionnel: Nettoyer aussi les entrées device_last_seen pour cet utilisateur s'il n'y a plus d'état actif
        if username in device_last_seen:
             del device_last_seen[username]


def is_device_online(username, device_type):
    """Vérifie si un appareil spécifique pour un utilisateur est considéré en ligne."""
    current_time = time.time()
    if username in device_last_seen and device_type in device_last_seen[username]:
        return current_time < device_last_seen[username][device_type] + DEVICE_TIMEOUT
    return False


# --- Routes pour l'interface utilisateur ---

@app.route('/')
def index():
    # Page de login avec lien vers l'inscription
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Connexion au Compte Cloud</title>
            <!-- Bootstrap CSS -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {
                    background-color: #f8f9fa;
                }
                .container {
                    max-width: 400px;
                    margin-top: 50px;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                h1, h2 {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .form-label {
                    font-weight: bold;
                }
                .alert {
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Accès au Compte Cloud</h1>
                <h2>Connexion</h2>
                <form action="/login" method="post">
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
                <p class="text-center mt-3"><a href="/register">Nouvel utilisateur? S'inscrire ici.</a></p>
                <div id="login-status" class="alert d-none" role="alert"></div>
            </div>

            <!-- Bootstrap JS (optionnel, pour certains composants Bootstrap) -->
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                // Script client-side pour afficher le statut de connexion
                document.querySelector('form[action="/login"]').addEventListener('submit', async function(event) {
                    event.preventDefault();
                    const form = event.target;
                    const formData = new FormData(form);
                    const response = await fetch(form.action, {
                        method: form.method,
                        body: formData
                    });
                    const result = await response.json();
                    const statusDiv = document.getElementById('login-status');

                    // Afficher le message
                    statusDiv.innerText = result.message;
                    statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger', 'alert-info'); // Nettoyer les classes précédentes

                    if (result.status === 'fail') {
                        statusDiv.classList.add('alert-danger'); // Rouge pour échec
                    } else if (result.status === '2fa_required') {
                         statusDiv.classList.add('alert-info'); // Bleu pour info/attente
                    }
                     statusDiv.classList.remove('d-none'); // Rendre visible

                    if (result.status === '2fa_required' && result.redirect_url) {
                        // Si 2FA requise, rediriger vers la page de saisie TOTP
                        // Ajouter un petit délai pour que l'utilisateur lise le message
                        setTimeout(() => {
                            window.location.href = result.redirect_url;
                        }, 2000); // Rediriger après 2 secondes
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
            <!-- Bootstrap CSS -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
             <style>
                body {
                    background-color: #f8f9fa;
                }
                .container {
                    max-width: 500px;
                    margin-top: 50px;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                h1, h2 {
                    text-align: center;
                    margin-bottom: 20px;
                }
                 .form-label {
                    font-weight: bold;
                }
                 .alert {
                    margin-top: 20px;
                 }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Inscription</h1>
                <form action="/register" method="post">
                    <div class="mb-3">
                        <label for="username" class="form-label">Nom d'utilisateur:</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Mot de passe:</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                     <div class="mb-3">
                        <label for="phone_number" class="form-label">Numéro de téléphone (pour SMS, format +12223334444):</label>
                        <input type="text" class="form-control" id="phone_number" name="phone_number">
                         <small class="form-text text-muted">Requis pour recevoir les codes TOTP et les alertes.</small>
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
                <p class="text-center mt-3"><a href="/">Retour à la connexion.</a></p>
                <div id="register-status" class="alert d-none" role="alert"></div>
            </div>

            <!-- Bootstrap JS (optionnel) -->
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                // Script client-side pour afficher le statut d'inscription
                document.querySelector('form[action="/register"]').addEventListener('submit', async function(event) {
                    event.preventDefault();
                    const form = event.target;
                    const formData = new FormData(form);
                    const response = await fetch(form.action, {
                        method: form.method,
                        body: formData
                    });
                    const result = await response.json();
                    const statusDiv = document.getElementById('register-status');

                    statusDiv.innerText = result.message;
                    statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger'); // Nettoyer les classes précédentes

                    if (response.ok) {
                        statusDiv.classList.add('alert-success'); // Vert pour succès
                    } else {
                        statusDiv.classList.add('alert-danger'); // Rouge pour échec
                    }
                    statusDiv.classList.remove('d-none'); // Rendre visible
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
    enabled_devices = request.form.getlist('device')

    if not username or not password:
        return jsonify({"message": "Nom d'utilisateur et mot de passe requis"}), 400

    if not enabled_devices:
         return jsonify({"message": "Veuillez sélectionner au moins un dispositif 2FA"}), 400

    if username in users:
        return jsonify({"message": "Nom d'utilisateur déjà existant"}), 409

    # Générer une clé secrète TOTP unique pour cet utilisateur
    totp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    users[username] = {
        'password_hash': generate_password_hash(password),
        'totp_secret': totp_secret, # Le secret est stocké sur le serveur ET sur les appareils
        'enabled_devices': enabled_devices,
        'phone_number': phone_number if phone_number else None
    }
    save_users(users)
    print(f"Utilisateur {username} enregistré. Dispositifs 2FA: {enabled_devices}. Secret TOTP: {totp_secret}")
    return jsonify({"message": f"Utilisateur enregistré avec succès. Votre secret TOTP est: {totp_secret}. Notez-le pour configurer vos appareils ({', '.join(enabled_devices)})!"}), 201

@app.route('/login', methods=['POST'])
def login():
    # Nettoyer les états expirés avant de traiter la nouvelle tentative
    cleanup_expired_states()

    username = request.form.get('username')
    password = request.form.get('password')

    user = users.get(username)

    if not user or not check_password_hash(user['password_hash'], password):
        # Échec de la vérification du mot de passe
        print(f"Échec de connexion (mot de passe) pour {username}: Identifiants invalides.")
        # Envoyer un SMS d'échec de tentative de connexion
        if user and user.get('phone_number'): # Envoyer SMS seulement si l'utilisateur existe et a un numéro
             send_sms(user['phone_number'], f"Tentative de connexion échouée pour votre compte cloud avec le nom d'utilisateur {username}.")
        elif not user:
             print(f"Tentative de connexion échouée pour utilisateur inconnu: {username}")

        # Mettre à jour l'état pour les appareils (échec)
        if username: # Éviter d'enregistrer un état pour un utilisateur None
             auth_states[username] = {'status': 'fail', 'timestamp': time.time()}

        # Retourner l'échec au navigateur
        return jsonify({"status": "fail", "message": "Nom d'utilisateur ou mot de passe invalide"}), 401
    else:
        # Mot de passe correct. La 2FA est requise.
        print(f"Mot de passe correct pour {username}. 2FA requise.")

        enabled_devices = user.get('enabled_devices', [])
        if not enabled_devices:
             # Cas improbable si l'inscription a bien fonctionné, mais sécurité
             print(f"Aucun appareil 2FA activé pour l'utilisateur {username}.")
             if user.get('phone_number'):
                  send_sms(user['phone_number'], f"Tentative de connexion échouée: Aucun appareil 2FA activé pour votre compte {username}.")
             auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
             return jsonify({"status": "fail", "message": "Aucun appareil 2FA configuré pour votre compte"}), 400

        # Vérifier quels appareils activés sont en ligne
        online_devices = [device for device in enabled_devices if is_device_online(username, device)]
        print(f"Appareils activés pour {username}: {enabled_devices}. Appareils en ligne: {online_devices}")

        if not online_devices:
             # Aucun appareil activé n'est en ligne
             print(f"Aucun appareil 2FA en ligne pour l'utilisateur {username}.")
             message = f"Tentative de connexion échouée: Aucun de vos appareils 2FA ({', '.join(enabled_devices)}) n'est actuellement en ligne. Veuillez vérifier vos appareils."
             if user.get('phone_number'):
                  send_sms(user['phone_number'], message)
             auth_states[username] = {'status': 'fail', 'timestamp': time.time()}
             return jsonify({"status": "fail", "message": message}), 400

        # Choisir aléatoirement un dispositif PARMI CEUX QUI SONT EN LIGNE
        chosen_device = random.choice(online_devices)
        print(f"Dispositif 2FA choisi aléatoirement parmi les appareils en ligne pour {username}: {chosen_device}")

        # Créer un token unique pour cette tentative 2FA (pour le navigateur)
        browser_token = str(uuid.uuid4())

        # Mettre à jour l'état pour les appareils et le navigateur
        auth_states[username] = {
            'status': 'awaiting_device_totp', # Le serveur attend que l'appareil envoie le TOTP
            'device': chosen_device,          # L'appareil attendu
            'browser_token': browser_token,   # Token pour lier la session navigateur à l'état
            'received_totp': None,            # Le TOTP reçu de l'appareil sera stocké ici
            'timestamp': time.time()
        }
        print(f"État pour {username} mis à jour: awaiting_device_totp (appareil attendu: {chosen_device})")


        # Rediriger le navigateur vers la page de saisie TOTP avec le token
        # L'utilisateur attendra sur cette page que le SMS arrive
        return jsonify({"status": "2fa_required", "message": f"Mot de passe correct. Veuillez attendre le code TOTP envoyé par SMS via votre appareil {chosen_device}.", "redirect_url": url_for('verify_totp_page', token=browser_token, _external=True)}), 200

@app.route('/verify_totp_page')
def verify_totp_page():
    # Page pour saisir le TOTP
    browser_token = request.args.get('token')

    # Trouver l'état de l'utilisateur basé sur le token du navigateur
    username = None
    for user, state_data in auth_states.items():
        if state_data.get('browser_token') == browser_token:
            username = user
            break

    if not username or username not in auth_states or time.time() > auth_states[username]['timestamp'] + STATE_TIMEOUT:
        print(f"Accès à verify_totp_page échoué: Token navigateur invalide ou état expiré pour token {browser_token}.")
        # Nettoyer l'état si trouvé mais expiré
        if username and username in auth_states:
             del auth_states[username]
        return "Requête invalide ou expirée. Veuillez recommencer la connexion.", 400 # Gérer les tokens manquants ou invalides

    # L'état existe et n'est pas expiré. Afficher la page de saisie TOTP.
    # Le message peut indiquer d'attendre le SMS si le TOTP n'a pas encore été reçu de l'appareil.
    state_data = auth_states[username]
    current_status = state_data['status']
    message = "Veuillez saisir le code TOTP reçu par SMS."
    if current_status == 'awaiting_device_totp':
        message = f"Mot de passe correct. Veuillez attendre que votre appareil {state_data.get('device', 'sélectionné')} génère et envoie le code TOTP."
    elif current_status == 'awaiting_user_totp_entry':
         message = f"Code TOTP reçu de votre appareil {state_data.get('device', 'sélectionné')}. Veuillez saisir le code TOTP reçu par SMS."
    # Si le statut est 'success' ou 'fail', l'utilisateur ne devrait pas être sur cette page,
    # mais la logique de redirection dans le JS gère cela.

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vérification 2FA</title>
            <!-- Bootstrap CSS -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
             <style>
                body {
                    background-color: #f8f9fa;
                }
                .container {
                    max-width: 400px;
                    margin-top: 50px;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                h1, h2 {
                    text-align: center;
                    margin-bottom: 20px;
                }
                 .form-label {
                    font-weight: bold;
                }
                 .alert {
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Vérification 2FA</h1>
                <p class="text-center" id="status-message">{{ message }}</p>
                <form action="/verify_totp" method="post">
                    <input type="hidden" name="token" value="{{ browser_token }}">
                    <div class="mb-3">
                         <label for="device_name" class="form-label">Nom de l'appareil (ex: pi ou esp32):</label>
                         <input type="text" class="form-control" id="device_name" name="device_name" required>
                    </div>
                    <div class="mb-3">
                         <label for="totp_code" class="form-label">Code TOTP reçu par SMS:</label>
                         <input type="text" class="form-control" id="totp_code" name="totp_code" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Vérifier le Code</button>
                </form>
                <div id="verification-status" class="alert d-none" role="alert"></div>
            </div>

            <!-- Bootstrap JS (optionnel) -->
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                // Script client-side pour afficher le statut de vérification
                document.querySelector('form[action="/verify_totp"]').addEventListener('submit', async function(event) {
                    event.preventDefault();
                    const form = event.target;
                    const formData = new FormData(form);
                    const response = await fetch(form.action, {
                        method: form.method,
                        body: formData
                    });
                    const result = await response.json();
                    const statusDiv = document.getElementById('verification-status');

                    statusDiv.innerText = result.message;
                    statusDiv.classList.remove('d-none', 'alert-success', 'alert-danger'); // Nettoyer les classes précédentes

                    if (result.status === 'success') {
                        statusDiv.classList.add('alert-success'); // Vert pour succès
                         // Rediriger après un petit délai
                         setTimeout(() => {
                            window.location.href = result.redirect_url;
                        }, 2000); // Rediriger après 2 secondes
                    } else {
                        statusDiv.classList.add('alert-danger'); // Rouge pour échec
                        // Si échec, l'utilisateur peut réessayer si l'état n'a pas expiré.
                        // Le message d'erreur est déjà affiché.
                    }
                    statusDiv.classList.remove('d-none'); // Rendre visible
                });
            </script>
        </body>
        </html>
    ''', browser_token=browser_token, message=message) # Passer le token et le message au template

@app.route('/verify_totp', methods=['POST'])
def verify_totp():
    # Nettoyer les états expirés
    cleanup_expired_states()

    browser_token = request.form.get('token')
    device_name_user_input = request.form.get('device_name') # Nom de l'appareil saisi par l'utilisateur
    totp_code_user_input = request.form.get('totp_code')     # Code TOTP saisi par l'utilisateur

    # Trouver l'état de l'utilisateur basé sur le token du navigateur
    username = None
    for user, state_data in auth_states.items():
        if state_data.get('browser_token') == browser_token:
            username = user
            break

    if not username or username not in auth_states or time.time() > auth_states[username]['timestamp'] + STATE_TIMEOUT:
        print(f"Vérification TOTP échouée: Token navigateur invalide ou état expiré pour token {browser_token}.")
        # Nettoyer l'état si trouvé mais expiré
        if username and username in auth_states:
             del auth_states[username]
        return jsonify({"status": "fail", "message": "Session de vérification expirée ou invalide. Veuillez recommencer la connexion."}), 400

    # L'état existe et n'est pas expiré.
    state_data = auth_states[username]

    # Vérifier si le TOTP a bien été reçu de l'appareil ET si l'état est correct
    received_totp = state_data.get('received_totp')
    chosen_device = state_data.get('device')

    if state_data['status'] != 'awaiting_user_totp_entry' or not received_totp or not chosen_device:
         print(f"Vérification TOTP échouée pour {username}: TOTP de l'appareil non encore reçu, état incorrect ({state_data['status']}), ou appareil non choisi.")
         # L'utilisateur a soumis le code trop tôt, avant que l'appareil ne l'envoie au serveur, ou il y a une erreur d'état.
         # Ne pas supprimer l'état, l'utilisateur peut réessayer.
         return jsonify({"status": "fail", "message": "Le code TOTP de votre appareil n'a pas encore été reçu par le serveur ou l'état est incorrect. Veuillez attendre le SMS et réessayer."}), 400


    # Vérifier le TOTP saisi par l'utilisateur ET le nom de l'appareil saisi
    if totp_code_user_input == received_totp and device_name_user_input == chosen_device:
        # 2FA réussie
        print(f"Vérification TOTP réussie pour {username}.")
        auth_states[username]['status'] = 'success' # Mettre à jour l'état
        auth_states[username]['timestamp'] = time.time() # Mettre à jour le timestamp pour la durée de la session
        # Envoyer un SMS de connexion réussie
        user = users.get(username)
        if user and user.get('phone_number'):
             send_sms(user['phone_number'], f"Connexion réussie à votre compte cloud.")

        # Retourner le succès au navigateur et l'URL de redirection
        return jsonify({"status": "success", "message": "Vérification 2FA réussie. Redirection vers votre espace cloud...", "redirect_url": url_for('cloud_space', _external=True)}), 200
    else:
        # TOTP ou nom d'appareil invalide
        print(f"Vérification TOTP échouée pour {username}: Code ({totp_code_user_input}) ou nom d'appareil ({device_name_user_input}) invalide.")
        auth_states[username]['status'] = 'fail' # Mettre à jour l'état
        auth_states[username]['timestamp'] = time.time() # Mettre à jour le timestamp pour la durée de l'échec
        # Ne pas supprimer l'état tout de suite pour permettre aux appareils de le voir.
        # Envoyer un SMS d'échec de 2FA
        user = users.get(username)
        if user and user.get('phone_number'):
             send_sms(user['phone_number'], f"Tentative de connexion échouée (code 2FA ou nom d'appareil invalide) pour votre compte cloud.")
        return jsonify({"status": "fail", "message": "Code TOTP ou nom d'appareil invalide."}), 401

# --- Point de terminaison pour que les appareils soumettent le TOTP ---

@app.route('/submit_device_totp', methods=['POST'])
def submit_device_totp():
    # Nettoyer les états expirés
    cleanup_expired_states()

    data = request.get_json()
    username = data.get('username')
    device_type = data.get('device_type') # 'pi' ou 'esp32'
    totp_code_from_device = data.get('totp')
    # Optionnel: Inclure un secret partagé ou une signature pour authentifier la requête de l'appareil

    print(f"TOTP reçu de l'appareil {device_type} pour l'utilisateur {username}: {totp_code_from_device}")

    if not username or not device_type or not totp_code_from_device:
        print("Soumission TOTP échouée: Données manquantes.")
        return jsonify({"status": "error", "message": "Données manquantes"}), 400

    # Trouver l'état de l'utilisateur
    state_data = auth_states.get(username)
    user = users.get(username) # Récupérer les données utilisateur complètes

    # Vérifier si l'utilisateur existe et si une tentative est en attente de TOTP de cet appareil
    if not user or not state_data or state_data['status'] != 'awaiting_device_totp' or state_data.get('device') != device_type:
        print(f"Soumission TOTP échouée pour {username} depuis {device_type}: Pas d'état en attente ou appareil incorrect.")
        # Optionnel: Envoyer un SMS d'alerte si un appareil non attendu soumet un code
        if user and user.get('phone_number'):
             send_sms(user['phone_number'], f"Alerte de sécurité: Tentative de soumission TOTP inattendue depuis un appareil ({device_type}) pour votre compte cloud.")
        return jsonify({"status": "fail", "message": "Aucune tentative de connexion en attente de TOTP de cet appareil"}), 400

    # L'appareil correct a soumis un code alors que le serveur l'attendait
    # Vérifier si le TOTP soumis par l'appareil est valide (basé sur le secret stocké sur le serveur)
    # C'est une double vérification. L'appareil génère le code, le serveur le vérifie aussi.
    totp_server_check = pyotp.TOTP(user['totp_secret'])
    if not totp_server_check.verify(totp_code_from_device):
         print(f"Soumission TOTP échouée pour {username} depuis {device_type}: Code TOTP invalide (vérification serveur).")
         # Mettre l'état en échec
         auth_states[username]['status'] = 'fail'
         auth_states[username]['timestamp'] = time.time()
         if user.get('phone_number'):
              send_sms(user['phone_number'], f"Tentative de connexion échouée (code 2FA invalide soumis par appareil) pour votre compte cloud.")
         return jsonify({"status": "fail", "message": "Code TOTP invalide"}), 401


    # Le TOTP de l'appareil est valide et attendu
    print(f"TOTP valide reçu de l'appareil {device_type} pour {username}.")
    # Stocker le code reçu pour la vérification ultérieure par l'utilisateur
    auth_states[username]['received_totp'] = totp_code_from_device
    # Mettre à jour l'état pour indiquer que le serveur attend maintenant la saisie de l'utilisateur
    auth_states[username]['status'] = 'awaiting_user_totp_entry'
    auth_states[username]['timestamp'] = time.time() # Mettre à jour le timestamp

    # Envoyer le code TOTP reçu par SMS à l'utilisateur (en mentionnant l'appareil)
    sms_message = f"Votre code TOTP pour votre compte cloud ({device_type}): {totp_code_from_device}. Saisissez-le sur la page de connexion."
    send_sms(user['phone_number'], sms_message)

    return jsonify({"status": "success", "message": "TOTP reçu et validé par le serveur. SMS envoyé."}), 200


# --- Point de terminaison pour les appareils IoT pour vérifier le statut ---

@app.route('/check_auth_status', methods=['POST'])
def check_auth_status():
    # Nettoyer les états expirés
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
    # print(f"Appareil {device_type} pour {username} vu à {time.ctime(device_last_seen[username][device_type])}") # Trop verbeux


    # Vérifier l'état pour cet utilisateur
    state_data = auth_states.get(username)

    if state_data and time.time() < state_data['timestamp'] + STATE_TIMEOUT:
        # Si un état récent et valide existe, le retourner
        status = state_data['status']
        response_data = {"status": status, "message": f"Statut d'authentification: {status}"}

        # Si le serveur attend le TOTP de cet appareil, inclure cette information
        if status == 'awaiting_device_totp' and state_data.get('device') == device_type:
             response_data['action'] = 'generate_and_submit_totp'
             response_data['message'] += f" - Veuillez générer et soumettre le TOTP."
             print(f"Statut pour {username} ({device_type}): {status} - Action: generate_and_submit_totp")
        elif status in ['success', 'fail']:
             response_data['action'] = 'stop_polling' # Indiquer à l'appareil d'arrêter
             print(f"Statut pour {username} ({device_type}): {status} - Action: stop_polling")
        else:
             response_data['action'] = 'wait' # Indiquer à l'appareil d'attendre
             # print(f"Statut pour {username} ({device_type}): {status} - Action: wait") # Trop verbeux


        # Optionnel: Supprimer l'état 'success' ou 'fail' après qu'un appareil l'ait récupéré
        # pour que les appareils arrêtent de réagir après la première notification.
        # if status in ['success', 'fail']:
        #      del auth_states[username]
        #      print(f"Statut {status} effacé pour {username} après récupération par {device_type}.")


        return jsonify(response_data), 200
    else:
        # Si aucun état récent, l'utilisateur n'est pas en cours d'authentification ou l'état a expiré
        # print(f"Aucun état récent pour {username}. Statut: not_authenticated") # Trop verbeux
        return jsonify({"status": "not_authenticated", "message": "Aucun statut d'authentification récent", "action": "wait"}), 200 # Retourner 200 même si pas authentifié, ce n'est pas une erreur

# --- Route pour l'espace cloud (protégée temporairement) ---

@app.route('/cloud_space')
def cloud_space():
    # Nettoyer les états expirés
    cleanup_expired_states()

    # Dans une vraie application, l'utilisateur serait identifié par une session sécurisée.
    # Ici, on utilise l'état temporaire basé sur le nom d'utilisateur.
    # L'utilisateur doit accéder à cette page APRÈS avoir réussi la 2FA.
    # On suppose que le nom d'utilisateur peut être passé en paramètre ou récupéré d'une manière ou d'une autre.
    # Pour simplifier, on va vérifier si *un* utilisateur est temporairement authentifié avec succès.
    # Une meilleure approche serait de lier l'état temporaire à une session navigateur.

    # Vérifier si au moins un utilisateur est temporairement authentifié avec succès
    # NOTE: Ceci est une simplification majeure de sécurité.
    authenticated_user = None
    current_time = time.time()
    # Parcourir les états pour trouver un succès non expiré
    for user, state_data in list(auth_states.items()): # Utiliser list() car le dict peut être modifié pendant l'itération
        if state_data['status'] == 'success' and current_time < state_data['timestamp'] + STATE_TIMEOUT:
            authenticated_user = user
            break # Trouver le premier utilisateur authentifié temporairement

    if authenticated_user:
        # Afficher la page de l'espace cloud
        # Optionnel: Effacer l'état de succès après l'accès (pour une seule utilisation)
        # if authenticated_user in auth_states:
        #      del auth_states[authenticated_user]
        #      print(f"État de succès effacé pour {authenticated_user} après accès à l'espace cloud.")

        return render_template_string(f'''
            <!DOCTYPE html>
            <html lang="fr">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Espace Cloud</title>
                <!-- Bootstrap CSS -->
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                 <style>
                    body {
                        background-color: #f8f9fa;
                    }
                    .container {
                        margin-top: 50px;
                        padding: 20px;
                        background-color: #ffffff;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    }
                    h1, h2 {
                        text-align: center;
                        margin-bottom: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Bienvenue dans votre Espace Cloud, {authenticated_user}!</h1>
                    <p>Ceci est votre espace personnel sécurisé.</p>
                    <p class="text-center mt-4"><a href="/" class="btn btn-danger">Se déconnecter (simulé - retourne à l'accueil)</a></p>
                </div>
                 <!-- Bootstrap JS (optionnel) -->
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''')
    else:
        # Rediriger vers la page de connexion si non authentifié temporairement
        print("Accès à l'espace cloud refusé: non authentifié temporairement.")
        return redirect(url_for('index')) # Rediriger vers la page d'accueil/connexion

# --- Exécution de l'application ---

if __name__ == '__main__':
    # Pour les tests locaux, décommenter la ligne ci-dessous et commenter les lignes Gunicorn
    # app.run(debug=True, host='0.0.0.0')

    # Pour le déploiement sur Render, Gunicorn sera configuré pour exécuter l'application.
    # Cette partie du code ne s'exécutera pas directement sur Render si vous utilisez un Procfile standard.
    print("Application Flask démarrée. Utilisez un serveur WSGI de production comme Gunicorn pour le déploiement.")
