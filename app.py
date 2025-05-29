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
    else:
        # Si le fichier n'existe pas, retourner un dictionnaire vide
        return {}

def save_users(users_data):
    """Sauvegarde les données des utilisateurs dans le fichier JSON."""
    # Utiliser 'w' pour écraser le contenu existant avec les nouvelles données
    with open(JSON_FILE_PATH, 'w') as f:
        json.dump(users_data, f, indent=4) # Utiliser indent pour une meilleure lisibilité

# Charger les utilisateurs au démarrage de l'application
# ATTENTION: Sur les services gratuits comme Render, ce fichier peut être réinitialisé
# à chaque redémarrage du service, entraînant la perte des utilisateurs enregistrés.
users = load_users()
print(f"Chargé {len(users)} utilisateurs depuis {JSON_FILE_PATH}")

# --- Gestion de l'état d'authentification temporaire ---
# Stocke les tentatives de connexion en attente de 2FA
# {token_unique: {'username': '...', 'device_type': '...', 'expected_totp': '...', 'timestamp': '...'}}
pending_2fa_verifications = {}
PENDING_TIMEOUT = 300 # Durée de validité de l'attente 2FA en secondes (5 minutes)

# Stocke l'état d'authentification final pour que les appareils puissent le consulter
# {username: {'status': 'success'/'fail', 'timestamp': '...'}}
recent_auth_status = {}
STATUS_TIMEOUT = 60 # Durée pendant laquelle l'état final est conservé pour les appareils (pour le polling des appareils)

def cleanup_expired_states():
    """Nettoie les états d'authentification temporaires expirés."""
    current_time = time.time()
    # Nettoyer les vérifications 2FA en attente expirées
    expired_pending_tokens = [token for token, data in pending_2fa_verifications.items() if current_time > data['timestamp'] + PENDING_TIMEOUT]
    for token in expired_pending_tokens:
        print(f"Nettoyage de la vérification 2FA en attente expirée pour {pending_2fa_verifications[token]['username']}")
        del pending_2fa_verifications[token]

    # Nettoyer les statuts d'authentification récents expirés
    expired_status_users = [username for username, data in recent_auth_status.items() if current_time > data['timestamp'] + STATUS_TIMEOUT]
    for username in expired_status_users:
        print(f"Nettoyage du statut d'authentification récent expiré pour {username}")
        del recent_auth_status[username]

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
        'totp_secret': totp_secret,
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

        # Mettre à jour le statut récent pour les appareils (échec)
        # Ceci permet au Pi/ESP32 de réagir même si le mot de passe initial échoue
        if username: # Éviter d'enregistrer un statut pour un utilisateur None
             recent_auth_status[username] = {'status': 'fail', 'timestamp': time.time()}

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
             recent_auth_status[username] = {'status': 'fail', 'timestamp': time.time()}
             return jsonify({"status": "fail", "message": "Aucun appareil 2FA configuré pour votre compte"}), 400

        # Choisir aléatoirement un dispositif activé
        chosen_device = random.choice(enabled_devices)
        print(f"Dispositif 2FA choisi aléatoirement pour {username}: {chosen_device}")

        # Générer le TOTP pour le secret de l'utilisateur
        totp = pyotp.TOTP(user['totp_secret'])
        current_totp = totp.now()
        print(f"TOTP généré pour {username} ({chosen_device}): {current_totp}")

        # Envoyer le TOTP à l'utilisateur via SMS
        sms_message = f"Votre code TOTP pour votre compte cloud ({chosen_device}): {current_totp}. Ce code est valide pendant une courte période."
        send_sms(user['phone_number'], sms_message)

        # Créer un token unique pour cette tentative 2FA
        auth_token = str(uuid.uuid4())

        # Stocker les informations de la tentative en attente
        pending_2fa_verifications[auth_token] = {
            'username': username,
            'device_type': chosen_device, # Stocker le type d'appareil choisi
            'expected_totp': current_totp,
            'timestamp': time.time()
        }
        print(f"Tentative 2FA en attente stockée avec le token: {auth_token}")

        # Mettre à jour le statut récent pour les appareils (en attente de 2FA)
        recent_auth_status[username] = {'status': 'pending_2fa', 'timestamp': time.time()}


        # Rediriger le navigateur vers la page de saisie TOTP avec le token
        return jsonify({"status": "2fa_required", "message": f"Mot de passe correct. Un code TOTP a été envoyé par SMS via votre appareil {chosen_device}. Veuillez le saisir.", "redirect_url": url_for('verify_totp_page', token=auth_token, _external=True)}), 200

@app.route('/verify_totp_page')
def verify_totp_page():
    # Page pour saisir le TOTP
    auth_token = request.args.get('token')
    if not auth_token or auth_token not in pending_2fa_verifications:
        return "Requête invalide ou expirée.", 400 # Gérer les tokens manquants ou invalides

    # Afficher le formulaire de saisie TOTP
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
                <p class="text-center">Veuillez saisir le code TOTP reçu par SMS.</p>
                <form action="/verify_totp" method="post">
                    <input type="hidden" name="token" value="{{ token }}">
                    <div class="mb-3">
                         <label for="totp_code" class="form-label">Code TOTP:</label>
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
                    }
                    statusDiv.classList.remove('d-none'); // Rendre visible
                });
            </script>
        </body>
        </html>
    ''', token=auth_token) # Passer le token au template

@app.route('/verify_totp', methods=['POST'])
def verify_totp():
    # Nettoyer les états expirés
    cleanup_expired_states()

    auth_token = request.form.get('token')
    totp_code = request.form.get('totp_code')

    # Récupérer les données de la tentative en attente
    pending_data = pending_2fa_verifications.get(auth_token)

    if not pending_data:
        print("Vérification TOTP échouée: Token invalide ou expiré.")
        # Ne pas envoyer de SMS ici car on ne sait pas à quel utilisateur l'associer de manière fiable
        return jsonify({"status": "fail", "message": "Session de vérification expirée ou invalide. Veuillez recommencer la connexion."}), 400

    username = pending_data['username']
    expected_totp = pending_data['expected_totp']
    user = users.get(username) # Récupérer les données utilisateur complètes

    if not user:
         # Cas improbable si pending_data existe mais pas l'utilisateur, mais sécurité
         print(f"Vérification TOTP échouée pour {username}: Utilisateur introuvable.")
         del pending_2fa_verifications[auth_token] # Nettoyer l'état
         recent_auth_status[username] = {'status': 'fail', 'timestamp': time.time()}
         if user and user.get('phone_number'):
              send_sms(user['phone_number'], f"Tentative de connexion échouée (utilisateur introuvable) pour votre compte cloud.")
         return jsonify({"status": "fail", "message": "Erreur interne. Veuillez recommencer la connexion."}), 500


    # Vérifier le TOTP saisi par l'utilisateur par rapport au code attendu
    # Note: On ne régénère PAS le TOTP ici, on compare avec celui qui a été envoyé par SMS.
    if totp_code == expected_totp:
        # 2FA réussie
        print(f"Vérification TOTP réussie pour {username}.")
        del pending_2fa_verifications[auth_token] # Nettoyer l'état en attente
        recent_auth_status[username] = {'status': 'success', 'timestamp': time.time()} # Mettre à jour le statut récent pour les appareils
        # Envoyer un SMS de connexion réussie
        if user.get('phone_number'):
             send_sms(user['phone_number'], f"Connexion réussie à votre compte cloud.")

        # Retourner le succès au navigateur et l'URL de redirection
        return jsonify({"status": "success", "message": "Vérification 2FA réussie. Redirection vers votre espace cloud...", "redirect_url": url_for('cloud_space', _external=True)}), 200
    else:
        # TOTP invalide
        print(f"Vérification TOTP échouée pour {username}: Code invalide.")
        # Ne pas supprimer l'état pending_2fa_verifications tout de suite pour permettre de réessayer
        # L'état expirera après PENDING_TIMEOUT.
        recent_auth_status[username] = {'status': 'fail', 'timestamp': time.time()} # Mettre à jour le statut récent pour les appareils
        # Envoyer un SMS d'échec de 2FA
        if user.get('phone_number'):
             send_sms(user['phone_number'], f"Tentative de connexion échouée (code 2FA invalide) pour votre compte cloud.")
        return jsonify({"status": "fail", "message": "Code TOTP invalide."}), 401

# --- Route pour les appareils IoT pour vérifier le statut ---

@app.route('/check_auth_status', methods=['POST'])
def check_auth_status():
    # Nettoyer les états expirés
    cleanup_expired_states()

    data = request.get_json()
    username = data.get('username')
    device_type = data.get('device_type') # Pour loguer quel appareil interroge

    if not username or not device_type:
        return jsonify({"status": "error", "message": "Nom d'utilisateur ou type d'appareil manquant"}), 400

    print(f"Requête de statut reçue pour {username} depuis {device_type}")

    # Vérifier le statut récent pour cet utilisateur
    status_data = recent_auth_status.get(username)

    if status_data:
        # Si un statut récent existe, le retourner
        status = status_data['status']
        print(f"Statut pour {username}: {status}")
        # Optionnel: Supprimer le statut après qu'un appareil l'ait récupéré pour une seule notification par appareil
        # del recent_auth_status[username] # Décommenter si vous voulez que chaque appareil ne réagisse qu'une fois
        return jsonify({"status": status, "message": f"Statut d'authentification: {status}"}), 200
    else:
        # Si aucun statut récent, l'utilisateur n'est pas en cours d'authentification ou le statut a expiré
        print(f"Aucun statut récent pour {username}. Statut: not_authenticated")
        return jsonify({"status": "not_authenticated", "message": "Aucun statut d'authentification récent"}), 200 # Retourner 200 même si pas authentifié, ce n'est pas une erreur

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
    # Parcourir les statuts récents pour trouver un succès non expiré
    for user, data in list(recent_auth_status.items()): # Utiliser list() car le dict peut être modifié pendant l'itération
        if data['status'] == 'success' and current_time < data['timestamp'] + STATUS_TIMEOUT:
            authenticated_user = user
            break # Trouver le premier utilisateur authentifié temporairement

    if authenticated_user:
        # Afficher la page de l'espace cloud
        # Optionnel: Effacer le statut de succès après l'accès (pour une seule utilisation)
        # if authenticated_user in recent_auth_status:
        #      del recent_auth_status[authenticated_user]
        #      print(f"Statut de succès effacé pour {authenticated_user} après accès à l'espace cloud.")

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
