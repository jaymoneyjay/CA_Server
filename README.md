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

This createds a hidden file $\texttt{.env}$ which contains an $\texttt{api-key}$ and $\texttt{api-pass}$ both of which have to be included in $\texttt{https}$ headers to authenticate successfully to the API:

```bash
Auth_Key: <<api-key>>
Auth_Pass: <<api-pass>>
Content-Type: application/json
```


Start the API with the following command

```bash
python3 ca_app.py
```
