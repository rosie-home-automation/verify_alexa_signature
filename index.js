var Promise = require('bluebird')
var Crypto = require('crypto')
var NormalizeUrl = require('normalizeurl')
var Request = Promise.promisify(request('request'))
var X509 = require('x509')

var SUBJECT_ALTERNATIVE_NAME = 'DNS:echo-api.amazon.com'
var SIGNATURE_CERT_URL_REGEX = new RegExp('^https://s3\.amazonaws\.com(:443)?\/echo.api\/')

var VerifyAlexaSignature = {
  certs: {},
  verify: function(signature, signatureCertUrl, body) {
    var self = this
    var deferred = Promise.pending()

    self.getCert(signatureCertUrl)
      .then(function(cert) {
        if (!self.validateCert(cert)) {
          deferred.reject('Invalid certificate.')
        }
        else if (!self.validateBody(cert, signature, body)) {
          deferred.reject('Invalid signature.')
        }
        else {
          deferred.resolve('Valid signature.')
        }
      })
      .catch(function(err) {
        deferred.reject(err)
      })

    return deferred
  },
  getCert: function(signatureCertUrl) {
    var deferred = Promise.pending()

    if (this.certs[signatureCertUrl]) {
      deferred.resolve(this.certs[signatureCertUrl])
    }
    else if (!this.validCertUrl(signatureCertUrl)) {
      deferred.reject('Invalid certificate URL.')
    }
    else {
      Request(signatureCertUrl).spread(function(response, body) {
        if (response.statusCode != 200) {
          deferred.reject('Non 200 response downloading certificate.')
        }
        else {
          var cert = X509.parseCert(body)
          this.certs[signatureCertUrl] = cert
          deferred.resolve(cert)
        }
      })
    }

    return deferred.promise
  },
  validateBody: function(cert, signature, body) {
    var date = new Date()
    if (Math.abs(date - body.request.timestamp) / 1000 > 150) { // timestamp is within 150 seconds of our time
      return false
    }
    var publicKey = cert.publicKey.n
    var verifier = Crypto.createVerify('SHA1')
    verifier.update(JSON.stringify(body))
    return verifier.verify(data, signature, 'base64')
  },
  validateCert: function(cert) {
    var date = new Date()
    if (cert.notBefore > date || cert.notAfter < date) {
      return false
    }
    var san = cert.extensions.subjectAlternativeName
    if (san !== SUBJECT_ALTERNATIVE_NAME) {
      return false
    }
    return true
  },
  validCertUrl: function(signatureCertUrl) {
    return SIGNATURE_CERT_URL_REGEX.test(signatureCertUrl)
  },
  purgeCerts: function() {
    this.certs = {}
  }
}

module.exports = VerifyAlexaSignature
