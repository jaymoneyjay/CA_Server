import flask, base64, enum
import random, os, json, argparse, logging
from ca_server import Ca_Server

from OpenSSL import SSL
from dotenv import load_dotenv, find_dotenv

SERVER_KEY_PATH = "root/server.key.pem"
SERVER_CERT_PATH = "root/server.cert.pem"

load_dotenv(find_dotenv())
API_AUTH = os.environ.get("CA_SERVER_CLIENT_AUTH")
API_KEY = os.environ.get("CA_SERVER_CLIENT_KEY")

class Privilege(enum.Enum):
    NONE = 0
    USER = 1

def main(args):

    app = flask.Flask(__name__)
    app.config["DEBUG"] = True
    logging.basicConfig(filename='ca_service.log', format='%(asctime)s %(message)s', level=logging.INFO)
    
    ca_server = Ca_Server()
    print(SERVER_KEY_PATH)


    #####
    # ROUTING
    #####
    @app.route('/', methods=['GET'])
    def home():
        return "<h1>iMovies PKI API Server</p>"

    @app.route('/certificates/verify', methods=['POST'])
    def verify_certificate():
        auth_key, auth_pass, args_json = _parse_request(flask.request)

        priv = _authenticate(auth_key, auth_pass)

        if priv == Privilege.NONE:
            return _error_forbidden()
        else:
            cert_b64 = args_json["cert"]["base64"]
            cert = base64.b64decode(cert_b64)
            is_valid = ca_server.verify_certificate(cert)

            return _response_certificate_status(is_valid)

    @app.route('/certificates/status', methods=['GET'])
    def get_status():
        auth_key, auth_pass, _ = _parse_request(flask.request)
        priv = _authenticate(auth_key, auth_pass)

        if priv == Privilege.NONE:
            return _error_forbidden()
        else:
            number_active, number_revoked, serial = ca_server.get_status()

            return _response_status(number_active, number_revoked, serial)

    @app.route('/certificates/serial', methods=['POST'])
    def get_certificate_subject():
        auth_key, auth_pass, args_json = _parse_request(flask.request)
        priv = _authenticate(auth_key, auth_pass)
        
        if priv == Privilege.NONE:
            return _error_forbidden()
        else:    
            serial_number = args_json["serial"]

            user_id = ca_server.get_certificate_subject(serial_number)

            if user_id is None:
                return _error_not_found()
            else:
                return _response_certificates_serial(user_id, serial_number
                )

    @app.route('/certificates', methods=['POST'])
    def get_certificates():
        auth_key, auth_pass, args_json = _parse_request(flask.request)
        priv = _authenticate(auth_key, auth_pass)

        if priv == Privilege.NONE:
            return _error_forbidden()
        else:
            user_id = args_json["user_id"]

            certs = ca_server.get_user_certificates_list(user_id)

            if certs is None:
                return _response_certificates([], user_id)
        
        return _response_certificates(certs, user_id)

    @app.route('/certificates/issue', methods=['POST'])
    def issue_certificate():

        auth_key, auth_pass, args_json = _parse_request(flask.request)
        priv = _authenticate(auth_key, auth_pass)

        if priv == Privilege.NONE:
            return _error_forbidden()
        else:
            first_name = args_json["firstname"]
            last_name = args_json["lastname"]
            email = args_json["email"]
            user_pw = args_json["password"]
            user_id = args_json["user_id"]

            serial_number, pkcs12_dump = ca_server.generate_user_certificate(args_json)
            pkcs12_b64 = base64.b64encode(pkcs12_dump).decode("ascii")
            
            # TODO: Encrypt and store private key to database

            return _response_issue(first_name, last_name, email, user_id, serial_number, pkcs12_b64)

    @app.route('/certificates/revoke', methods=['POST'])
    def revoke_certificate():

        auth_key, auth_pass, args_json = _parse_request(flask.request)
        priv = _authenticate(auth_key, auth_pass)

        if priv == Privilege.NONE:
            return _error_forbidden()
        else:
            serial = args_json["serial"]

            if ca_server.revoke_user_certificate(serial):
                return _response_revoke(serial)
            else:
                return _error_not_found()

    @app.route('/certificates/crl', methods=['GET'])
    def get_crl():
        auth_key, auth_pass, _ = _parse_request(flask.request)
        priv = _authenticate(auth_key, auth_pass)

        if priv == Privilege.NONE:
            return _error_forbidden()
        else:

            crl = ca_server.get_crl()
            crl_64 = base64.b64encode(crl.encode("ascii")).decode("ascii")
            return _response_crl(crl_64)


    def _parse_request(request):
        request_headers = request.headers

        user_id = request_headers["Auth-Key"]
        user_pw = request_headers["Auth-Pass"]

        logging.info(f"Request from {user_id}")

        request_json = request.json

        return user_id, user_pw, request_json

    def _authenticate(api_auth, api_key):
        if api_auth == API_AUTH and api_key == API_KEY:
            return Privilege.USER
        else:
            return Privilege.NONE

    def _generate_config(user_id, first_name, last_name, email):
        config = f"""
        FQDN = www.iMovies.ch
        ORGNAME = iMovies
        ALTNAMES = DNS:$FQDN

        # --- no modifications required below ---
        [ req ]
        default_bits = 2048
        default_md = sha256
        prompt = no
        encrypt_key = no
        distinguished_name = dn
        req_extensions = req_ext

        [ dn ]
        C = CH
        O = $ORGNAME
        CN = {first_name} {last_name}
        emailAddress = {email}
        
        [ req_ext ]
        subjectAltName = $ALTNAMES
        """
        
        return config

    #####
    # RESPONSES
    #####
    
    def _response_crl(crl_64):
        response = {
            "status": "ok",
            "crl64": crl_64
        }

        logging.info(f"Status ok. Responded with crl in base64.")

        return flask.Response(json.dumps(response), status=200, mimetype='application/json')

    def _response_status(number_active, number_revoked, current_serial):
        response = {
            "status": "ok",
            "result": {
                "number_active": number_active,
                "number_revoked": number_revoked,
                "current_serial": current_serial
            }
        }

        logging.info(f"Status ok. Responded with active: {number_active}, revoked: {number_revoked}, current serial: {current_serial}")

        return flask.Response(json.dumps(response), status=200, mimetype='application/json')

    def _response_certificates(certificates, user_id):
        results = []
        for cert in certificates:
            result = {
                "serial": cert[0],
                "fingerprint": cert[1],
                "valid": cert[2]
            }
            results.append(result)
        
        response = {
            "status": "ok",
        }

        response["result_length"] = len(results)
        response["result"] = results

        logging.info(f"Status ok. Responded with list of user certificates of user {user_id}.")
        
        return flask.Response(json.dumps(response), status=200, mimetype='application/json')
        
    def _response_issue(firstname, lastname, email, user_id, serial, pkcs12_b64):
        response = {
            "status": "ok",
            "message": "Certificate issued",
            "result": {
                "firstname": firstname,
                "lastname": lastname,
                "email": email,
                "user_id": user_id,
                "serial": serial,
                "key": {
                    "file_name": f"{serial}.p12",
                    "base64": pkcs12_b64
                }
            }
        }

        logging.info(f"Status ok. Certificate {serial}.p12 generated successfully for user {user_id}.")

        return flask.Response(json.dumps(response), status=200, mimetype='application/json')

    def _response_revoke(serial):
        response = {
            "status": "ok",
            "message": f"Certificate {serial} revoked"
        }

        logging.info(f"Status ok. Certificate {serial}.p12 successfully revoked.")
        
        return flask.Response(json.dumps(response), status=200, mimetype='application/json')
    
    def _response_certificate_status(is_valid):
        response = {
            "status": "ok",
            "valid": is_valid
        }

        logging.info(f"Status ok. Responded with certificate revoked status.  Valid: {is_valid}")

        return flask.Response(json.dumps(response), status=200, mimetype='application/json')

    def _response_certificates_serial(user_id, serial_number):
        response = {
            "status": "ok",
            "user_id": user_id
        }

        logging.info(f"Status ok. Responded with user id corresponding to certificate {serial_number}.p12: user_id")

        return flask.Response(json.dumps(response), status=200, mimetype='application/json')

    #####
    # ERRORS
    #####
    def _error_unauthorized():
        response = {
            "status": "error",
            "message": "Unauthorized"
        }

        logging.info(f"Status error: 401 unauthorized")

        return flask.Response(json.dumps(response), status=401, mimetype='application/json')
    
    def _error_forbidden():
        response = {
            "status": "error",
            "message": "Forbidden"
        }

        logging.info(f"Status error: 403 forbidden")

        return flask.Response(json.dumps(response), status=403, mimetype='application/json')
    
    def _error_server_internal():
        response = {
            "status": "error",
	        "message": "Internal Server Error"
        }

        logging.info(f"Status error: 500 internal server error")

        return flask.Response(json.dumps(response), status=500, mimetype='application/json')

    def _error_not_found():
        response = {
            "status": "error",
	        "message": "Not found"
        }

        logging.info(f"Status error: 404 not found")
        
        return flask.Response(json.dumps(response), status=404, mimetype='application/json')

    #app.run(host="0.0.0.0", port="5000", ssl_context=(SERVER_CERT_PATH, SERVER_KEY_PATH))
    app.run(host="0.0.0.0", port="5000")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    main(args)