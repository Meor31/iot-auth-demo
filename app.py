# app.py
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
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
# Stocke les tentatives de connexion en attente de code
# {username: {'device': '...', 'code': '...', 'browser_token': '...', 'timestamp': '...'}}
auth_states = {}
STATE_TIMEOUT = 300 # Durée de validité d'un état en secondes (5 minutes)

def cleanup_expired_states():
    """Nettoie les états d'authentification temporaires expirés."""
    current_time = time.time()
    expired_users = [username for username, data in auth_states.items() if current_time > data['timestamp'] + STATE_TIMEOUT]
    for username in expired_users:
        print(f"Nettoyage de l'état expiré pour {username} (statut: en attente de code)")
        del auth_states[username]

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
                    } else if (result.status === 'code_required') {
                         statusDiv.classList.add('alert-info'); // Bleu pour info/attente
                    }
                     statusDiv.classList.remove('d-none'); // Rendre visible

                    if (result.status === 'code_required' && result.redirect_url) {
                        // Si code requise, rediriger vers la page de saisie du code
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
                         <small class="form-text text-muted">Requis pour recevoir les codes et les alertes.</small>
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

    if not username or not password:
        return jsonify({"message": "Nom d'utilisateur et mot de passe requis"}), 400

    if username in users:
        return jsonify({"message": "Nom d'utilisateur déjà existant"}), 409

    # Pas de secret TOTP ici, car on n'utilise plus TOTP

    users[username] = {
        'password_hash': generate_password_hash(password),
        'phone_number': phone_number if phone_number else None
    }
    save_users(users)
    print(f"Utilisateur {username} enregistré.")
    return jsonify({"message": "Utilisateur enregistré avec succès."}), 201

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

        # Retourner l'échec au navigateur
        return jsonify({"status": "fail", "message": "Nom d'utilisateur ou mot de passe invalide"}), 401
    else:
        # Mot de passe correct. Générer un code et attendre la soumission.
        print(f"Mot de passe correct pour {username}. Génération d'un code et envoi par SMS.")

        # Générer un code aléatoire
        random_code = str(random.randint(100000, 999999))

        # Créer un token unique pour cette tentative
        auth_token = str(uuid.uuid4())

        # Stocker les informations de la tentative en attente
        auth_states[username] = {
            'status': 'awaiting_code',
            'code': random_code,
            'browser_token': auth_token,
            'timestamp': time.time()
        }

        # Envoyer le code à l'utilisateur par SMS
        sms_message = f"Votre code de connexion pour votre compte cloud: {random_code}. Saisissez-le sur la page de connexion."
        send_sms(user['phone_number'], sms_message)

        # Rediriger le navigateur vers la page de saisie du code avec le token
        return jsonify({"status": "code_required", "message": "Mot de passe correct. Un code a été envoyé par SMS. Veuillez le saisir.", "redirect_url": url_for('verify_code_page', token=auth_token, _external=True)}), 200

@app.route('/verify_code_page')
def verify_code_page():
    # Page pour saisir le code
    auth_token = request.args.get('token')
    if not auth_token or not auth_token in auth_states:
        return "Requête invalide ou expirée.", 400 # Gérer les tokens manquants ou invalides

    # Afficher le formulaire de saisie du code
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vérification du Code</title>
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
                <h1>Vérification du Code</h1>
                <p class="text-center">Veuillez saisir le code reçu par SMS.</p>
                <form action="/verify_code" method="post">
                    <input type="hidden" name="token" value="{{ token }}">
                    <div class="mb-3">
                         <label for="code" class="form-label">Code:</label>
                         <input type="text" class="form-control" id="code" name="code" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Vérifier le Code</button>
                </form>
                <div id="verification-status" class="alert d-none" role="alert"></div>
            </div>

            <!-- Bootstrap JS (optionnel) -->
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                // Script client-side pour afficher le statut de vérification
                document.querySelector('form[action="/verify_code"]').addEventListener('submit', async function(event) {
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
                        // Si échec, l'utilisateur peut réessayer si la tentative n'a pas expiré.
                    }
                    statusDiv.classList.remove('d-none'); // Rendre visible
                });
            </script>
        </body>
        </html>
    ''', token=auth_token) # Passer le token au template

@app.route('/verify_code', methods=['POST'])
def verify_code():
    # Nettoyer les états expirés
    cleanup_expired_states()

    browser_token = request.form.get('token')
    code_user_input = request.form.get('code')

    # Récupérer les données de la tentative en attente
    state_data = auth_states.get(browser_token)

    if not state_data:
        print("Vérification du code échouée: Token invalide ou expiré.")
        # Ne pas envoyer de SMS ici car on ne sait pas à quel utilisateur l'associer de manière fiable
        return jsonify({"status": "fail", "message": "Session de vérification expirée ou invalide. Veuillez recommencer la connexion."}), 400

    username = state_data['username']
    expected_code = state_data['code']
    user = users.get(username) # Récupérer les données utilisateur complètes

    if not user:
         # Cas improbable si state_data existe mais pas l'utilisateur, mais sécurité
         print(f"Vérification du code échouée pour {username}: Utilisateur introuvable.")
         del auth_states[browser_token] # Nettoyer l'état
         # recent_auth_status[username] = {'status': 'fail', 'timestamp': time.time()} # Pas de statut pour les appareils ici
         if user and user.get('phone_number'):
              send_sms(user['phone_number'], f"Tentative de connexion échouée (utilisateur introuvable) pour votre compte cloud.")
         return jsonify({"status": "fail", "message": "Erreur interne. Veuillez recommencer la connexion."}), 500


    # Vérifier le code saisi par l'utilisateur par rapport au code attendu
    if code_user_input == expected_code:
        # Vérification réussie
        print(f"Vérification du code réussie pour {username}.")
        del auth_states[browser_token] # Nettoyer l'état en attente
        # recent_auth_status[username] = {'status': 'success', 'timestamp': time.time()} # Pas de statut pour les appareils ici
        # Envoyer un SMS de connexion réussie
        if user.get('phone_number'):
             send_sms(user['phone_number'], f"Connexion réussie à votre compte cloud.")

        # Retourner le succès au navigateur et l'URL de redirection
        return jsonify({"status": "success", "message": "Vérification réussie. Redirection vers votre espace cloud...", "redirect_url": url_for('cloud_space', _external=True)}), 200
    else:
        # Code invalide
        print(f"Vérification du code échouée pour {username}: Code invalide.")
        # Ne pas supprimer l'état pending_2fa_verifications tout de suite pour permettre de réessayer
        # L'état expirera après PENDING_TIMEOUT.
        # recent_auth_status[username] = {'status': 'fail', 'timestamp': time.time()} # Pas de statut pour les appareils ici
        # Envoyer un SMS d'échec
        if user.get('phone_number'):
             send_sms(user['phone_number'], f"Tentative de connexion échouée (code invalide) pour votre compte cloud.")
        return jsonify({"status": "fail", "message": "Code invalide."}), 401

# --- Nouveau point de terminaison pour que les appareils soumettent le code ---

@app.route('/submit_code', methods=['POST'])
def submit_code():
    data = request.get_json()
    username = data.get('username')
    device_type = data.get('device_type')
    code = data.get('code')

    print(f"Code reçu de l'appareil {device_type} pour l'utilisateur {username}: {code}")

    # Trouver l'état de l'utilisateur
    state_data = auth_states.get(username)
    user = users.get(username)

    # Vérifier si l'utilisateur existe et si une tentative est en attente
    if not user or not state_data or state_data['status'] != 'awaiting_code':
        print(f"Soumission du code échouée pour {username} depuis {device_type}: Pas d'état en attente.")
        return jsonify({"status": "fail", "message": "Pas de tentative de connexion en attente"}), 400

    # Stocker le code reçu
    state_data['code'] = code
    print(f"Code stocké pour {username}.")
    return jsonify({"status": "success", "message": "Code reçu et stocké par le serveur."}), 200

# --- Route pour l'espace cloud (protégée temporairement) ---

@app.route('/cloud_space')
def cloud_space():
    # Nettoyer les états expirés
    cleanup_expired_states()

    # Dans une vraie application, l'utilisateur serait identifié par une session sécurisée.
    # Ici, on utilise l'état temporaire basé sur le nom d'utilisateur.
    # L'utilisateur doit accéder à cette page APRÈS avoir réussi la vérification du code.

    # Vérifier si au moins un utilisateur est temporairement authentifié avec succès
    authenticated_user = None
    for user, data in list(auth_states.items()): # Utiliser list() car le dict peut être modifié pendant l'itération
        if data['status'] == 'success' and time.time() < data['timestamp'] + STATE_TIMEOUT:
            authenticated_user = user
            break # Trouver le premier utilisateur authentifié temporairement

    if authenticated_user:
        # Afficher la page de l'espace cloud
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
                    body {{
                        background-color: #f8f9fa;
                    }}
                    .container {{
                        margin-top: 50px;
                        padding: 20px;
                        background-color: #ffffff;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    }}
                    h1, h2 {{
                        text-align: center;
                        margin-bottom: 20px;
                    }}
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
    # Utiliser le serveur de développement Flask pour les tests locaux
    # app.run(debug=True, host='0.0.0.0')

    # Pour le déploiement sur Render, Gunicorn sera configuré pour exécuter l'application.
    # Cette partie du code ne s'exécutera pas directement sur Render si vous utilisez un Procfile standard.
    print("Application Flask démarrée. Utilisez un serveur WSGI de production comme Gunicorn pour le déploiement.")
