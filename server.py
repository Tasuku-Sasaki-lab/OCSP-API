from flask import Flask
from flask import request
from flask import make_response
import utils
from cryptography.x509 import load_pem_x509_certificate, ocsp

app = Flask(__name__)


'''
OCSP (Online Certificate Status Protocol) is a method of checking the revocation status of certificates. It is specified in RFC 6960, as well as other obsoleted RFCs.
'''

@app.route('/ocsp',methods=['POST'])
def ocspServer():
    successFlag = True
    if request.content_type != 'application/ocsp-request':
        return make_response("malformed header", 400)
    try:
        #classcryptography.x509.ocsp.OCSPRequest[source] New in version 2.4
        #An OCSPRequest is an object containing information about a certificate whose status is being checked.
        ocsp_req = ocsp.load_der_ocsp_request(request.get_data())
    except Exception as e:
        res  = make_response(utils.createRequestUnsuccessfull('malformed'), 400)
        successFlag = False

    try:
        if not utils.authorise(ocsp_req):
            res  = make_response(utils.createRequestUnsuccessfull('sig_required'), 400)
            successFlag = False
    except Exception as e:
        res  = make_response(utils.createRequestUnsuccessfull('inernal_error'), 500)
        successFlag = False

    if successFlag:
        res = make_response(utils.check(ocsp_req.serial_number),200)
    res.headers['content_type'] = 'application/ocsp-response'
    return res




if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8000)