import os
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL, SIMPLE
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

LDAP_URL = os.getenv("LDAP_URL")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
AUTH_SECRET = os.getenv("AUTH_SECRET")

@app.route("/passwordImport", methods=["POST"])
def password_import():
    auth_header = request.headers.get("Authorization")
    if auth_header != AUTH_SECRET:
        return "Unauthorized", 403

    data = request.get_json()
    try:
        username = data["data"]["context"]["credential"]["username"]
        password = data["data"]["context"]["credential"]["password"]
    except (KeyError, TypeError):
        return jsonify({"error": "Invalid payload"}), 400

    print(f"Attempting LDAP auth for: {username}")

    if validate_user(username, password):
        print("LDAP auth successful")
        return jsonify({
            "commands": [
                {
                    "type": "com.okta.action.update",
                    "value": {
                        "credential": "VERIFIED"
                    }
                }
            ]
        })
    else:
        print("LDAP auth failed")
        return "", 204

def validate_user(username, password):
    try:
        server = Server(LDAP_URL, get_info=ALL)
        conn = Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)

        search_filter = f"(|(sAMAccountName={username})(userPrincipalName={username})(mail={username})(uid={username}))"
        conn.search(LDAP_BASE_DN, search_filter, attributes=["distinguishedName"])

        if not conn.entries:
            print("User not found in LDAP search")
            return False

        user_dn = conn.entries[0].entry_dn
        print(f"Found user DN: {user_dn}")

        user_conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE)
        if user_conn.bind():
            user_conn.unbind()
            return True
        else:
            print("Bind as user failed")
            return False

    except Exception as e:
        print(f"LDAP error: {e}")
        return False

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
