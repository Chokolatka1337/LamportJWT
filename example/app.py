from flask import Flask, request, jsonify
from lamport_jwt.jwt import LamportJWT, InvalidTokenError, SignatureVerificationError

app = Flask(__name__)
LamportJWT.generate_private_key("private_key.json")
 
@app.route('/generate_token', methods=['POST'])
def generate_token():
    try:
        payload = request.get_json()
        if not isinstance(payload, dict):
            return jsonify({"error": "Payload must be a dictionary"}), 400
        
        token = LamportJWT.encode(payload)
        return jsonify({"token": token}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/verify_token', methods=['POST'])
def verify_token():
    try:
        token = request.json.get("token")
        if not token:
            return jsonify({"error": "Token is required"}), 400
        
        decoded_payload = LamportJWT.decode(token)
        return jsonify({"payload": decoded_payload}), 200

    except InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 400
    except SignatureVerificationError:
        return jsonify({"error": "Invalid token signature"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
