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
        os.system(f"touch {cert_path}")
        os.system(f"echo \"{cert}\" > {cert_path}")
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