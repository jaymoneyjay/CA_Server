# Ca_Server
The Ca Server provides an API to issue and revoke user certificates.

## Installation
Use the packet manager to install the following packets:

```bash
pip3 install flask b64 argparse python-dotenv
```
## Usage
First set up the chain of trust by running the following command. As SECRET you should provide a password to encrypt the private key of the root CA.

```bash
./set_up_ca.sh root.cnf intermediate.cnf <SECRET>
```

This creates the needed certificates and API credentials used for authentication:

```bash
Auth-Key: <API_CLIENT_KEY>
Auth-Pass: <API_CLIENT_PASS>
Content-Type: application/json
```
Create a `.env` file in the app's root directory with the following contents (with filling in the generated data from the previous step)
:
 ```bash
LISTEN="0.0.0.0"
PORT=5000
SSL_KEY_FILE="caserver.key.pem"
SSL_CERT_FILE="caserver.cert.pem"
LOGFILE="ca_server.log"
API_CLIENT_KEY="<API_CLIENT_KEY>"
API_CLIENT_PASS="<API_CLIENT_PASS>"
 ```


Start the API with the following command

```bash
python3 ca_app.py
```
