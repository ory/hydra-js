/* global process */
const jwt = require('jsonwebtoken')
const OAuth2 = require('simple-oauth2')
const request = require('superagent')
const jwkToPem = require('jwk-to-pem')

require('superagent-auth-bearer')(request)

class Hydra {
  constructor(config = {}) {
    let {
      client: {
        id: clientId = process.env.HYDRA_CLIENT_ID,
        secret: clientSecret = process.env.HYDRA_CLIENT_SECRET
      } = {},
      auth: {
        tokenHost: endpoint = process.env.HYDRA_URL,
        authorizePath: authorizePath = '/oauth2/auth',
        tokenPath: tokenPath = '/oauth2/token'
      } = {},
      scope: scope = 'hydra.keys.get',
      options: {
        useBodyAuth: useBodyAuth = false,
        useBasicAuthorizationHeader: useBasicAuthorizationHeader = true
      } = {}
    } = config

    this.config = {
      client: {
        id: clientId,
        secret: clientSecret
      },
      auth: {
        tokenHost: endpoint,
        authorizePath: authorizePath,
        tokenPath: tokenPath
      },
      options: {
        useBodyAuth,
        useBasicAuthorizationHeader
      }
    }

    this.scope = scope
    this.endpoint = endpoint
    this.token = null
  }

  authenticate() {
    if (this.token !== null && !this.token.expired()) {
      return Promise.resolve(this.token)
    }

    this.oauth2 = OAuth2.create(this.config)
    return this.oauth2.clientCredentials.getToken({ scope: this.scope }).then((result) => {
      this.token = this.oauth2.accessToken.create(result)
      return Promise.resolve(this.token)
    })
  }


  getKey(set, kid) {
    return this.authenticate().then(() => request
      .get(`${this.endpoint}/keys/${set}/${kid}`)
      .authBearer(this.token.token.access_token)
      .then((res) => !res.ok
        ? Promise.reject({ error: new Error('Status code is not 2xx'), message: 'Could not retrieve validation key.' })
        : Promise.resolve(res.body.keys[0])
      )
    )
  }

  verifyConsentChallenge(challenge = '') {
    return this.getKey('hydra.consent.challenge', 'public').then((key) => {
      return new Promise((resolve, reject) => {
        jwt.verify(challenge, jwkToPem(key), (error, decoded) => {
          if (error) {
            reject({ error, message: 'Could not verify consent challenge.' })
            return
          }
          resolve({ challenge: decoded })
        })
      })
    })
  }

  generateConsentResponse(challenge, subject, scopes, at = {}, idt = {}) {
    return this.verifyConsentChallenge(challenge).then(({ challenge }) => {
      return this.getKey('hydra.consent.response', 'private').then((key) => {
        return new Promise((resolve, reject) => {
          const { aud, exp, jti } = challenge
          jwt.sign({
            jti,
            aud,
            exp,
            scp: scopes,
            sub: subject,
            at_ext: at,
            id_ext: idt
          }, jwkToPem(Object.assign({}, key, {
            // the following keys are optional in the spec but for some reason required by the library.
            dp: '', dq: '', qi: ''
          }), { private: true }), { algorithm: 'RS256' }, (error, token) => {
            if (error) {
              reject({ error, message: 'Could not verify consent challenge.' })
              return
            }
            resolve({ consent: token })
          })
        })
      })
    })
  }

  getClient(id) {
    return this.authenticate().then(() => request
      .get(`${this.endpoint}/clients/${id}`)
      .authBearer(this.token.token.access_token)
      .then((res) => !res.ok
        ? Promise.reject({ error: new Error('Status code is not 2xx'), message: 'Could not retrieve client.' })
        : Promise.resolve(res.body)
      )
    )
  }

  validateToken(token) {
    return this.authenticate().then(() => request
      .post(`${this.endpoint}/oauth2/introspect`)
      .send(`token=${token}`)
      .authBearer(this.token.token.access_token)
      .then((res) => !res.ok
        ? Promise.reject({ error: new Error('Status code is not 2xx'), message: 'Introspection failed.' })
        : Promise.resolve(res.body)
      )
    )
  }
}

module.exports = Hydra
