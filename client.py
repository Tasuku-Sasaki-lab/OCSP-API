import requests
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate, ocsp
import base64
import os

def createRequest():
    return 0

def verify(ocsp_resp):
    cert_path = os.environ.get('CERT_PATH_CLIENT', 'depot/nssdc.crt')
    issuer_cert_path = os.environ.get('ISSUER_CERT_PATH_CLIENT', 'depot/ca.pem')
    try:
        with open(cert_path) as f:
            pem_cert  = f.read().encode()
        with open(issuer_cert_path) as f:
            pem_issuer  = f.read().encode()
    except Exception as e:
        exit(str(e))

    try:
        cert = load_pem_x509_certificate(pem_cert)
        issuer = load_pem_x509_certificate(pem_issuer)
    except Exception as e:
        exit(str(e))

    digestName.update(issuer.issuer.public_bytes())
    digestKey = hashes.Hash(ocsp_req.hash_algorithm)
    digestKey.update(issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1))
    
    if digestName.finalize() != ocsp_req.issuer_name_hash:
        return False
    if digestKey.finalize() != ocsp_req.issuer_key_hash:
        return False
    return True

def client():
    cert_path = os.environ.get('CERT_PATH_CLIENT', 'depot/nssdc.crt')
    issuer_cert_path = os.environ.get('ISSUER_CERT_PATH_CLIENT', 'depot/ca.pem')
    try:
        with open(cert_path) as f:
            pem_cert  = f.read().encode()
        with open(issuer_cert_path) as f:
            pem_issuer  = f.read().encode()
    except Exception as e:
        exit(str(e))
    #Create Request
    try:
        cert = load_pem_x509_certificate(pem_cert)
        issuer = load_pem_x509_certificate(pem_issuer)
    except Exception as e:
        exit(str(e))
    try:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        req = builder.build()
        req_data =req.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        exit(str(e))

    headers = {
        'Content-Type': 'application/ocsp-request'
    }

    url = os.environ.get('RESPONDER_URL', 'http://localhost:8000/ocsp')
    try:
        r = requests.post(url, data=req_data,headers=headers)
        print(r.content)
        print(type(r.content))
        ocsp_resp = ocsp.load_der_ocsp_response(r.content)
        print(ocsp_resp.response_status)
    except requests.HTTPError as e:
        exit(str(e))
    
    #Verify
    try:
        if (ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL):
            digestName = hashes.Hash(ocsp_resp.hash_algorithm)
            digestName.update(issuer.issuer.public_bytes())
            digestKey = hashes.Hash(ocsp_resp.hash_algorithm)
            digestKey.update(issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1))
    
            if ocsp_resp.hash_algorithm is hashes.SHA256():
                exit('Hash algorithm mismatch')
            if digestName.finalize() != ocsp_resp.issuer_name_hash:
                exit('Issuer name hash mismatch')
            if digestKey.finalize() != ocsp_resp.issuer_key_hash:
                exit('Issuer key hash mismatch')       
            if cert.serial_number != ocsp_resp.serial_number:
                exit('Serial number mismatch')
    except Exception as e:
        exit(str(e))

    return  req

if __name__ == '__main__':
    client()