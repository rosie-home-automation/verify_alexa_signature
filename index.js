'use strict'

let Promise = require('bluebird')
let Crypto = require('crypto')
let NormalizeUrl = require('normalizeurl')
let Request = Promise.promisify(request('request'))
let X509 = require('x509')

const SUBJECT_ALTERNATIVE_NAME = 'DNS:echo-api.amazon.com'
const SIGNATURE_CERT_URL_REGEX = new RegExp('^https://s3\.amazonaws\.com(:443)?\/echo.api\/')

let VerifyAlexaSignature = {
  certs: {},
  verify (signature, signatureCertChainUrl, body) {
    return new Promise((reject, resolve) => {
        this.getCert(signatureCertChainUrl)
          .then((cert) => {
            if (!this.validateCert(cert)) {
              reject('Invalid certificate.')
            }
            else if (!this.validateBody(cert, signature, body)) {
              reject('Invalid signature.')
            }
            else {
              resolve('Valid signature.')
            }
          })
    })
  },
  getCert (signatureCertChainUrl) {
    return new Promise((resolve, reject) => {
      let url = NormalizeUrl(signatureCertChainUrl)
      if (this.certs[url]) {
        resolve(this.certs[url])
      }
      else if (!this.validCertUrl(url)) {
        reject('Invalid certificate URL.')
      }
      else {
        Request(url).spread((response, body) => {
          if (response.statusCode != 200) {
            reject('Non 200 response downloading certificate.')
          }
          else {
            let cert = X509.parseCert(body)
            this.certs[url] = cert
            resolve(cert)
          }
        })
      }
    })
  },
  validateBody (cert, signature, body) {
    let date = new Date()
    if (Math.abs(date - body.request.timestamp) / 1000 > 150) { // timestamp is within 150 seconds of our time
      return false
    }
    let publicKey = cert.publicKey.n
    let verifier = Crypto.createVerify('SHA1')
    verifier.update(JSON.stringify(body))
    return verifier.verify(data, signature, 'base64')
  },
  validateCert (cert) {
    let date = new Date()
    if (cert.notBefore > date || cert.notAfter < date) {
      return false
    }
    let san = cert.extensions.subjectAlternativeName
    if (san !== SUBJECT_ALTERNATIVE_NAME) {
      return false
    }
    return true
  },
  validCertUrl (signatureCertChainUrl) {
    return SIGNATURE_CERT_URL_REGEX.test(signatureCertChainUrl)
  },
  purgeCerts () {
    this.certs = {}
  }
}

module.exports = VerifyAlexaSignature
