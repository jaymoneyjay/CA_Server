# source: https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html

import os
class Ca_Server:

    def __init__(self):
        self.ROOT = "root"
        self.INTERM = os.path.join(self.ROOT, "intermediate")
        self.CONFIG_INTERM = os.path.join(self.INTERM, "openssl.cnf")
        self.CONFIG_ROOT = os.path.join(self.ROOT, "openssl.cnf")
        self.INDEX = os.path.join(self.INTERM, "index.txt")
        self.SERIAL = os.path.join(self.INTERM, "serial")
        
        self.SERIAL_MIN = 4096

        self.CERTS = os.path.join(self.INTERM, "certs")
        self.KEYS = os.path.join(self.INTERM, "private")
        self.CSR = os.path.join(self.INTERM, "csr")
        self.CRL = os.path.join(self.INTERM, "crl/intermediate.crl.pem")
        self.CHAIN = os.path.join(self.INTERM, "certs/ca-chain.cert.pem")
        self.VERIFY = os.path.join(self.INTERM, "certs/crl_chain.cert.pem")

    
    def _find_cert(self, serial_number):
        # if not self._is_serial(serial_number):
        #     return None
        # serial_number = hex(serial_number).strip("0x")

        certs = self.get_all_certificates()
        for cert in certs:
            cert_name = os.path.basename(cert)
            other_serial = cert_name.split("@")[0]
            if serial_number == other_serial:
                cert_path = os.path.join(self.CERTS, cert)
                return cert_path
        return None

    def _is_serial(self, character):
        try:
            int(character)
            return True
        except ValueError:
            return False

    def _get_current_serial(self):
        return os.popen(f"cat {self.SERIAL}").read().strip("\n")

    def _create_crl(self):
        os.system(f"openssl ca -config {self.CONFIG_INTERM} \
                    -gencrl -out {self.CRL}")

    def generate_user_certificate(self, user_data):
        user_id = user_data["user_id"]
        email = user_data["email"]
        password = user_data["password"]
        first_name = user_data["firstname"].replace(" ", "")
        last_name = user_data["lastname"].replace(" ", "")
        
        # Read serial in HEX
        serial = self._get_current_serial()
        subject_option = f"/CN={serial}/O=iMovies/C=CH/ST=Zurich/L=Zurich/emailAddress={email}/OU={user_id}/surname={last_name}/givenName={first_name}"

        key_out = os.path.join(self.KEYS, f"{serial}@{user_id}.key.pem")
        request_out = os.path.join(self.CSR, f"{serial}@{user_id}.csr.pem")
        cert_out = os.path.join(self.CERTS, f"{serial}@{user_id}.cert.pem")
        pkcs12_out = os.path.join(self.CERTS, f"{serial}@{user_id}.12")
        
        print("generate key pair")
        # Generate key pair
        os.system(f"openssl genrsa -aes256 \
                    -passout pass:{password} -out {key_out} 2048")
        
        print("certificate request")
        # Generate certificate request
        os.system(f"openssl req -config {self.CONFIG_INTERM} \
                    -key {key_out} -passin pass:{password} \
                    -new -sha256 -subj {subject_option} \
                    -out {request_out}")
        
        print("sign cert")
        # sign certificate
        os.system(f"openssl ca -batch -config {self.CONFIG_INTERM} \
                    -extensions server_cert -days 375 -notext -md sha256 \
                    -in {request_out} \
                    -out {cert_out}")

        print("export to pkcs12")
        os.system(f"openssl pkcs12 -export -inkey {key_out} \
                    -passin pass:{password} -passout pass:{password} \
                    -in {cert_out} -out {pkcs12_out}")

        with open(pkcs12_out, "rb") as f:
            pkcs_dump = f.read()
        return serial, pkcs_dump

    def get_user_certificates(self, user_id):
        certs = self.get_all_certificates()
        user_certs = []
        for cert in certs:
            cert_name = os.path.basename(cert).strip(".cert.pem")
            other_id = cert_name.split("@")[-1]
            if other_id == user_id:
                cert_path = os.path.join(self.CERTS, cert)
                user_certs.append(cert_path)

        if user_certs == []:
            return None

        return user_certs

    def get_all_certificates(self):
        certs = []
        for f in os.listdir(self.CERTS):
            if f.endswith(".cert.pem"):
                certs.append(f)
        
        return certs
        
    def revoke_user_certificate(self, serial_number):
        crt = self._find_cert(serial_number)

        if crt is None:
            return False

        os.system(f"openssl ca -config {self.CONFIG_INTERM} \
                    -revoke {crt}")
        
        self._create_crl()

        return True

    def get_status(self):
        # TODO: is current serial last issued or next issued serial?
        serial_number = hex(int(self._get_current_serial(), 16) - 1).strip("0x").strip("\n")
        number_active = 0
        number_revoked = 0
        with open(self.INDEX) as f:
            lines = f.readlines()
            for line in lines:
                status = line[:1]
                if status == "V":
                    number_active+=1
                if status == "R":
                    number_revoked+=1

        return number_active, number_revoked, serial_number

    def get_crl(self):
        self._create_crl()
        return os.popen(f"openssl crl -in {self.CRL} -noout -text").read()

    def verify_certificate(self, cert):
        cert_path = os.path.join(self.CERTS, "temp.cert.pem")
        with open(cert_path, "wb") as f:
            f.write(cert)
        # update crl chain list
        _ = self.get_crl()
        os.system(f"cat {self.CHAIN} {self.CRL} > {self.VERIFY}")
        response = os.popen(f"openssl verify -crl_check -CAfile {self.VERIFY} {cert_path}").read()
        user_id = os.popen(f"openssl x509 -noout -subject -nameopt multiline -in {cert_path} | sed -n 's/organizationalUnitName[^=]*=//p'").read()
        user_id = user_id.strip()
        os.remove(cert_path)
        if response.endswith("OK\n"):
            return True, user_id
        else:
            return False, ""

    def get_certificate_subject(self, serial_number):
        cert_path = self._find_cert(serial_number)
        if cert_path is None:
            return None
        user_id = os.popen(f"openssl x509 -noout -subject -nameopt multiline -in {cert_path} | sed -n 's/organizationalUnitName[^=]*=//p'").read()
        user_id = user_id.strip()
        return user_id

    def get_user_certificates_list(self, user_id):
        users_certs_list = []
        user_certs = self.get_user_certificates_with_status(user_id)
        
        if user_certs is None:
            return None

        for cert_triple in user_certs:
            serial_number = cert_triple[0]
            user_id = cert_triple[1]
            status = cert_triple[2]
            cert_name = serial_number + "@" + user_id + ".cert.pem"
            cert_path = os.path.join(self.CERTS, cert_name)
            fingerprint = os.popen(f"openssl x509 -in {cert_path} -noout -fingerprint -sha256").read().strip("\n")
            fingerprint = fingerprint.replace("Fingerprint=", "")
            users_certs_list.append((serial_number, fingerprint, status))
        return users_certs_list

    def get_user_certificates_with_status(self, user_id):
        certs = self.get_all_certificates_with_status()
        user_certs = [cert for cert in certs if cert[1] == user_id]
        return user_certs

    def get_all_certificates_with_status(self):
        index_txt = os.popen(f"cat {self.INDEX}").readlines()
        certs = []
        user_delimiter = "/OU="
        for line in index_txt:
            if user_delimiter in line:
                status_str = line[0]
                status = (status_str == "V")
                user_id = line.split(user_delimiter, 1)[1].split("/")[0]
                serial_number = line.split("\t")[3]
                certs.append((serial_number, user_id, status))
        return certs


            





user_data = {
    "firstname": "Samuel",
    "lastname": "Waeny",
    "password": "test",
    "email": "waeny@imovies.ch",
    "user_id": "waeny"
}
cert_rev = """
-----BEGIN CERTIFICATE-----
MIIFoDCCA4igAwIBAgICEBEwDQYJKoZIhvcNAQELBQAwSjELMAkGA1UEBhMCQ0gx
DzANBgNVBAgMBlp1cmljaDEQMA4GA1UECgwHaU1vdmllczEYMBYGA1UEAwwPSW50
ZXJtZWRpYXRlIENBMB4XDTIwMTEwMzEyNDgzMloXDTIxMTExMzEyNDgzMlowgYEx
CzAJBgNVBAYTAkNIMQ8wDQYDVQQIDAZadXJpY2gxDzANBgNVBAcMBlp1cmljaDEQ
MA4GA1UECgwHaU1vdmllczEOMAwGA1UECwwFd2FlbnkxDTALBgNVBAMMBDEwMTEx
HzAdBgkqhkiG9w0BCQEWEHdhZW55QGltb3ZpZXMuY2gwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDuMSsR0zm3yH0tzd3vq9YlOnGF5uGUT0gNhhVlJR3s
Yct11LTDkh3F1v6dupTQ78gT5+saR8BaPweOjSo44+OEt5AKJwbTL3kyFxhGD5A+
Sxj4EVPJxUfU+ZArxijS35GxSid7d6NWmsDqMIYikdIno8DMojSN9d0xECf0cov2
ZKgeSc8dALOr9WamKvMT+A+N5OhLnwKCGZcedmzmzTN7kHqT6dTh9XafyJmRDtQa
eRaYv1P+SpVoBnKWlylPwEZfQNuoPzFStUi6CEZg149hXlBXpdvxhg8XkoEtRyy6
YLN4XElDItP11COwUbT/arFcJ0XtPZ+W+2koHtwIVtcLAgMBAAGjggFWMIIBUjAJ
BgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkT3Bl
blNTTCBHZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQbvDKV
LepV30KkRhEbqQFqeFVhpDB8BgNVHSMEdTBzgBRHWyJnNZkcrJiaP6t6lNTZUyOC
D6FXpFUwUzEQMA4GA1UEAwwHUm9vdCBDQTEQMA4GA1UECgwHaU1vdmllczELMAkG
A1UEBhMCQ0gxDzANBgNVBAgMBlp1cmljaDEPMA0GA1UEBwwGWnVyaWNoggIQADAO
BgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwOwYDVR0fBDQwMjAw
oC6gLIYqaHR0cDovLzEyNy4wLjAuMTo1MDAwL2ludGVybWVkaWF0ZS5jcmwucGVt
MA0GCSqGSIb3DQEBCwUAA4ICAQAQHA7HN/59FgoAOuvATUP+Rv146CeLvcjZ9MLi
ArP5k1hAcE1W2gD73DHEFwl5w4l4AsUliR0yAwDzirVlCyr+eGAfYJhxx0Uinzai
AoopEJAPuI7XF9LaihQFwq24TVUrFR6/j6VvnZPsqB+NT8eZkst5W6vv9/9vjmUa
ms97qT7/leTYeKmnQqMRJycklrlOXqUAIyQAI/ADuZnTjnFC99apKCbsvQrkRFs+
1MNmQCV/Zi1O99YH8VxXZXhLqs6S997cvKDCE/SLNpmayJOXFoUELldCzeZ1d70e
D3QPyfcmSHLa/UavP3khGSRQWOXeKCiWIzvRSYiZRWhqWeSF5DcCzqZMgZ2sZGfJ
AfrBszllqo2vDXBPvtK1i9OutU68AkffUji04mqBAh0OL/MacpMsPJJXVxHJEEt+
zEUhL7tcqLbfvn2tifzAsUHRWBnXsCGyXv4BslHuvwreDtVKD7z5YgcHNjhlTdlX
q9CdhH5rbK33h9lybj9qD/6ax/njkyEpJ+jgJG8Yz5yfNEjYRpkOdX8/+vnWGXsL
nVCUIhX4MtP3sv6yPkKAB8KprMrxjIIUj7g51d1xgNM3Wmib2sgrJXAwHhFF5jV6
ARAGV0oSVMSNvDs0k/SPb2eOKd5ELJdgSKU00GWS3vM/oZlbN/SAN/UZauX1Zuc2
KJjJng==
-----END CERTIFICATE-----
"""
cert_valid = """
-----BEGIN CERTIFICATE-----
MIIFnTCCA4WgAwIBAgICEBYwDQYJKoZIhvcNAQELBQAwSjELMAkGA1UEBhMCQ0gx
DzANBgNVBAgMBlp1cmljaDEQMA4GA1UECgwHaU1vdmllczEYMBYGA1UEAwwPSW50
ZXJtZWRpYXRlIENBMB4XDTIwMTEwMzEyNTY1OFoXDTIxMTExMzEyNTY1OFowfzEL
MAkGA1UEBhMCQ0gxDzANBgNVBAgMBlp1cmljaDEPMA0GA1UEBwwGWnVyaWNoMRAw
DgYDVQQKDAdpTW92aWVzMQ4wDAYDVQQLDAV3YWVueTENMAsGA1UEAwwEMTAxNjEd
MBsGCSqGSIb3DQEJARYOd2FlbnlzQGV0aHouY2gwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDpCz5HOXrGbYCHJqowxZlxoLU/lIV6TyCHKbs9te6xjZr8
1WRXga2trS5GsqDis+mGAkPyaXs6hFCJEFMB09u8OW69vFRBKOun6XVR33HDWvc1
MY7KyzbqkW+0HFEkg4OmkWAWFcQpbD97kuLVaSFsz1ZQn4J/yPPI583fU9h+dxbJ
sKx7weQjo4L2dg68qoyCWbZnNi+xsNEoL6rIBcytSe9RSumDgMyRMaqh35hMhZtW
2rbBjNdc66FSiI6tK7jcD6xxGBUokOMLAEYmsO0zhAG6AZmO3D5KkW0qmymXJ3U2
xqrzlHVhErEOo2vbUlMDUfphoditWS9IQKNCso7pAgMBAAGjggFWMIIBUjAJBgNV
HRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkT3BlblNT
TCBHZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBRA5HOWNIhD
XkdfpGLagJJ0zs2yBTB8BgNVHSMEdTBzgBRHWyJnNZkcrJiaP6t6lNTZUyOCD6FX
pFUwUzEQMA4GA1UEAwwHUm9vdCBDQTEQMA4GA1UECgwHaU1vdmllczELMAkGA1UE
BhMCQ0gxDzANBgNVBAgMBlp1cmljaDEPMA0GA1UEBwwGWnVyaWNoggIQADAOBgNV
HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwOwYDVR0fBDQwMjAwoC6g
LIYqaHR0cDovLzEyNy4wLjAuMTo1MDAwL2ludGVybWVkaWF0ZS5jcmwucGVtMA0G
CSqGSIb3DQEBCwUAA4ICAQCD07+65HF4kZE4T+GroY/ZDD7Zt73rvqko6i0Im2/Q
cFuvjajw0t5cDnY9ayKb09dByiKABPMDl5CEObDHAG2LklcXIeBunAAAKXy6AtLd
R7u+ODA0IjBMCxlHnLTeeeAJo7Dv8f+IfDmgyHTlURUBs2t82kYveg8arIvWtgLP
LDd2JPnX3Jg70YHy4yc+W71Z4jfjQbbGLHOfGRDYccIEy5K2emwidT4EtiauTgob
VfS01nnmqXRymrSzWI9n6qNzgBm16yDbaa+pEhWO0ha287jL+vgbLGPH5Re6qMGd
lC5NiXRQQfKU+LYmhWrbgUh5RSEYXxJVsq8x45Yk3CLqfQOvUUC8vUKTLaYpDHTg
nzPDyOH3zaHTaagDocvxZ/U6bE1v0tujZo9mC+er3u9TK2pC0ty9kjCc/QeEiSVv
m2KXKCWhSjGsqOXj/1vcUAop6LbYSjKh0/NHCugrNNvgqIkF5Wb2ZgYJ9ng5ix8k
d9WW73fGeg3dKmI4ktUnNN8or1iB2Ghz4ohDp4CDpF5zLaUs2oLicA94vp3wg3vF
LjNyDGNcBwlC0ClSvGouv5TQ+AJdfUKeeWnxNx8okGrA0CY4+tiQFLQD3s/WmbDp
7R1OxgWDMmknqLikG58lc/hkNkAh6A0aoXkBUL9dH/Qr0EUGwgWfgsYnjM9+oSzd
CQ==
-----END CERTIFICATE-----
"""

ca_server = Ca_Server()
#print(ca_server.get_user_certificates_list("waeny"))
#print(ca_server.get_certificate_subject("1013"))
#ca_server.generate_user_certificate(user_data)
#print(ca_server.revoke_certificate(4100))
#serial, pkcs12 = ca_server.generate_user_certificate("waeny", user_data)
#print(serial, pkcs12)
