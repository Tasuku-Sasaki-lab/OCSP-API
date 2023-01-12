from mongo import Mongo
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate, ocsp,ReasonFlags
import base64
import os

def authorise(ocsp_req):
    issuer_path = os.environ.get('ISSUER_CERT_PATH_SERVER', 'depot/ca.pem')
    with open(issuer_path ) as f:
        pem_issuer  = f.read().encode()
    issuer = load_pem_x509_certificate(pem_issuer)
    digestName = hashes.Hash(ocsp_req.hash_algorithm)
    digestName.update(issuer.issuer.public_bytes())
    digestKey = hashes.Hash(ocsp_req.hash_algorithm)
    digestKey.update(issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1))
    
    if digestName.finalize() != ocsp_req.issuer_name_hash:
        return False
    if digestKey.finalize() != ocsp_req.issuer_key_hash:
        return False
    return True

def check(serialNumber):
    mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
    mongo = Mongo(mongo_url,"devices_db","devices")
    DIFF_JST_FROM_UTC = 9
    time = datetime.datetime.now() + datetime.timedelta(hours=DIFF_JST_FROM_UTC)
    
    try:
        device = mongo.getOne({'serial': serialNumber })
    except Exception as e:
        return createRequestUnsuccessfull('inernal_error')

    if device is None:
        return createRequestUnsuccessfull('unauthorized')
    if (device['cert_not_after'] >  time):
        status =  'good'
        return createResponse(status,None,time,device['pem'])
    else:
        status = 'revoked'
        reason = ReasonFlags.ca_compromise
        return createResponse(status,reason,time,device['pem'],device['cert_not_after'])

def createRequestUnsuccessfull(status):
    if status == "malformed":
        #May be returned by an OCSP responder that is unable to parse a given request.
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.MALFORMED_REQUEST
        )
    elif status == "inernal_error":
        #May be returned by an OCSP responder that is currently experiencing operational problems.
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.INTERNAL_ERROR
        )
    elif status == "try_later":
        #May be returned by an OCSP responder that is overloaded.
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.TRY_LATER
        )
    elif status == "sig_required":
        #May be returned by an OCSP responder that requires signed OCSP requests.
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.SIG_REQUIRED
        )
    elif status == "unauthorized":
        #May be returned by an OCSP responder when queried for a certificate for which the responder is unaware or an issuer for which the responder is not authoritative.
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED
        )
    return response.public_bytes(serialization.Encoding.DER)
#revokasion time を渡す
def createResponse(status,reason,time,pem_cert_string,cert_not_after=None):
    pem_cert = pem_cert_string.encode()
    issuer_cert_path = os.environ.get('ISSUER_CERT_PATH_SERVER', 'depot/ca.pem')
    issuer_key_path = os.environ.get('ISSUER_KEY_PATH_SERVER', 'depot/ca.key')
    try:
        with open(issuer_cert_path) as f:
            pem_issuer  = f.read().encode()
            pem_responder_cert = pem_issuer
        with open(issuer_key_path) as f:
            pem_responder_key = f.read().encode()
    except Exception as e:
        return createRequestUnsuccessfull('inernal_error')
    try:
        cert = load_pem_x509_certificate(pem_cert)
        issuer = load_pem_x509_certificate(pem_issuer)
        responder_cert = load_pem_x509_certificate(pem_responder_cert) #今回は同じになるだろう
        responder_key = serialization.load_pem_private_key(pem_responder_key, None)
        builder = ocsp.OCSPResponseBuilder()

        # SHA256 is in this example because while RFC 5019 originally
        # required SHA1 RFC 6960 updates that to SHA256.
        # However, depending on your requirements you may need to use SHA1
        # for compatibility reasons.
        if status == "good":
            builder = builder.add_response(
                cert=cert, issuer=issuer, algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=time,
                next_update=None,
                revocation_time=None, revocation_reason=None
            ).responder_id(
                ocsp.OCSPResponderEncoding.HASH, responder_cert
            )
        #https://cryptography.io/en/latest/x509/reference/#cryptography.x509.ReasonFlags
        elif  status == "revoled":
                builder = builder.add_response(
                cert=cert, issuer=issuer, algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.REVOKED,
                this_update=time,
                next_update=None,
                revocation_time=cert_not_after, revocation_reason=reason
            ).responder_id(
                ocsp.OCSPResponderEncoding.HASH, responder_cert
            )
        else :
                builder = builder.add_response(
                cert=cert, issuer=issuer, algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.UNKNOWN,
                this_update=time,
                next_update=None,
                revocation_time=None, revocation_reason=None
            ).responder_id(
                ocsp.OCSPResponderEncoding.HASH, responder_cert
            )


        response = builder.sign(responder_key, hashes.SHA256())
        return response.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        print(e)
        return createRequestUnsuccessfull('inernal_error')

