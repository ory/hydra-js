/* global process */
const jwt = require('jsonwebtoken')
const OAuth2 = require('simple-oauth2')
const request = require('superagent')
const jwkToPem = require('jwk-to-pem')

require('superagent-auth-bearer')(request)

class Hydra {
  constructor(config) {
    this.config = Object.assign({
      client: {
        id: process.env.HYDRA_CLIENT_ID,
        secret: process.env.HYDRA_CLIENT_SECRET,
      },
      auth: {
        tokenHost: process.env.HYDRA_URL,
        authorizePath: '/oauth2/auth',
        tokenPath: '/oauth2/token'
      }
    }, config)
    this.endpoint = this.config.auth.tokenHost
    this.token = null
  }

  authenticate() {
    return new Promise((resolve, reject) => {
      if (this.token !== null && !this.token.expired()) {
        return resolve(this.token)
      }

      this.oauth2 = OAuth2.create(this.config)
      this.oauth2.clientCredentials.getToken({ scope: 'hydra.keys.get' }, (error, result) => {
        if (error) {
          return reject({ message: 'Could not retrieve access token: ' + error.message })
        }

        this.token = this.oauth2.accessToken.create(result)
        return resolve(this.token)
      })
    })
  }

  getKey(set, kid) {
    return new Promise((resolve, reject) => {
      return this.authenticate().then(() => {
        request.get(`${this.endpoint}/keys/${set}/${kid}`).authBearer(this.token.token.access_token).end((err, res) => {
          if (err || !res.ok) {
            reject({ error: 'Could not retrieve validation key: ' + err.message })
            return
          }
          resolve(res.body.keys[0])
        })
      })
    })
  }

  verifyConsentChallenge(challenge = '') {
    return new Promise((resolve, reject) => {
      return this.getKey('hydra.consent.challenge', 'public').then((key) => {
        jwt.verify(challenge, jwkToPem(key), (error, decoded) => {
          if (error) {
            reject({ error: 'Could not verify consent challenge: ' + error })
            return
          }
           resolve({ challenge: decoded })
        })
      })
    })
  }

  generateConsentResponse(challenge, subject, scopes, at = {}, idt = {}) {
    return new Promise((resolve, reject) => {
      return this.verifyConsentChallenge(challenge).then(({challenge}) => {
        return this.getKey('hydra.consent.response', 'private').then((key) => {
          const { aud, exp, jti } = challenge
          jwt.sign({ jti, aud, exp, scp: scopes, sub: subject, at_ext: at, id_ext: idt }, jwkToPem(Object.assign({}, key, {
            // the following keys are optional in the spec but for some reason required by the library.
            dp: '', dq: '', qi: ''
          }), { private: true }), { algorithm: 'RS256' }, (error, token) => {
            if (error) {
              reject({ error: 'Could not verify consent challenge: ' + error })
              return
            }
            resolve({ consent: token })
          })
        })
      })
    })
  }
}

module.exports = Hydra
