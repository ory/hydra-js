var Hydra = require('./hydra.js')
var nock = require('nock')
var jwtDecode = require('jwt-decode')
var jwt = require('jsonwebtoken')
var jwkToPem = require('jwk-to-pem')

describe('services', () => {
  describe('Hydra', () => {
    process.env.HYDRA_CLIENT_ID = 'default_client'
    process.env.HYDRA_CLIENT_SECRET = 'defulat_secret'
    process.env.HYDRA_URL = 'http://default.localhost'
    const defaults = {
      client: {
        id: process.env.HYDRA_CLIENT_ID,
        secret: process.env.HYDRA_CLIENT_SECRET,
      },
      auth: {
        tokenHost: process.env.HYDRA_URL,
        authorizePath: '/oauth2/auth',
        tokenPath: '/oauth2/token'
      },
      scope: 'hydra.keys.get'
    }

    const config = {
      client: {
        id: 'client',
        secret: 'secret'
      },
      auth: {
        tokenHost: 'http://foo.localhost',
        authorizePath: '/oauth2/auth',
        tokenPath: '/oauth2/token'
      },
      scope: 'foo'
    }

    test('constructor should override default values', () => {
      const h = new Hydra(config)
      expect(h.config).toEqual({client: config.client, auth: config.auth})
      expect(h.endpoint).toEqual(config.auth.tokenHost)
      expect(h.scope).toEqual(config.scope)
    })

    test('constructor should keep default values', () => {
      const h = new Hydra()
      expect(h.config).toEqual({client: defaults.client, auth: defaults.auth})
      expect(h.endpoint).toEqual(defaults.auth.tokenHost)
      expect(h.scope).toEqual(defaults.scope)
    })

    test('constructor should allow parital override of default values', () => {
      const expectedUrl = 'http://bar.localhost'
      const expectedId = 'foo'

      const h = new Hydra({
        client: {id: expectedId},
        auth: {tokenHost: expectedUrl}
      })
      expect(h.config).toEqual({
        client: {
          id: expectedId,
          secret: defaults.client.secret
        },
        auth: {
          tokenHost: expectedUrl,
          authorizePath: defaults.auth.authorizePath,
          tokenPath: defaults.auth.tokenPath
        }
      })
      expect(h.endpoint).toEqual(expectedUrl)
      expect(h.scope).toEqual(defaults.scope)
    })

    // set up oauth2 endpoint
    nock('http://foo.localhost').post('/oauth2/token').times(100).reply(200, {
      "access_token": "2YotnFZFEjr1zCsicMWpAA",
      "token_type": "bearer",
      "expires_in": 3600,
      "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
      "example_parameter": "example_value"
    })

    test('getKey() should fetch JWKs from the backend', () => {
      const key = {
        "keys": [
          {
            "kty": "RSA",
            "kid": "public",
            "n": "w7l1pEtWDCi6GeIqNrc90mqDSz1t8J8m5ylYGMZd2lrDFHo4SgXCxjubkdIU2mqn7nm0-alSGFxGxZO1xwywyTOJolNljWqok68_UagWnUVKyWpKLOgKVAJyK1P91LZj9pcRomEoO7c2TtUVIOf1Q3_7cIOYYFL6saluUyRhM8AEMZYq7IzYf5X6eHoz5kop5dt38ezPAiwMjWVcPDom1c0f9X7IVREiSK41Bz1HyoD958CpFJreaXtWevCuCSZZ3K6W0sEsy-fkIb8Zzmq_wfjLja-WHdqH03jZuJL9cEl8tFVgQsw_V8kvcvBHnmzAQQ2VzR2VKo3JYETv1uq1yjhjKb4ObmY5g8MiZ9Dun0NQe7ppN5HitFq96DCLSQfPOznpgPOc9k2GwfLlveOar7o0Dh2_ifAe7mEVHE-hMkJ1WyiEW3kNHz3HuJWJVWjfDo7JDl12BBtd7m-6YeUhesk1CUjb5MnKhoT79T9slYT5wMkbFMLcHHMx8QIcjS-hbhmaUZSwKlNOMiWZrirGi6g_nthWJPOBAkeF7re08a-0Jxk_29ZI6be_bPf28C9WdrnBhndzrFTLtleMeZ8l8pNkWu30qt9wjaWk9ZLS2q-oXYLYXEsSLFYGBjM_oawlv4xxnHEE3qjGlLu_zRG_kzhWlj1E_Tmk7YF9boLQUt0",
            "e": "AQAB"
          }
        ]
      }
      nock('http://foo.localhost').get('/keys/foo/bar').reply(200, key)

      const h = new Hydra(config)
      return h.getKey('foo', 'bar').then((got) => {
        expect(got).toEqual(key['keys'][0])
      })
    })

    test('getClient() should fetch a client from the backend', () => {
      const client = {
        dummy: true
      }
      nock('http://foo.localhost').get('/clients/foo').reply(200, client)

      const h = new Hydra(Object.assign({scope: 'hydra.clients'}, config))
      return h.getClient('foo').then((got) => {
        expect(got).toEqual(client)
      })
    })

    test('validateToken() token introspection', () => {
      nock('http://foo.localhost').post('/oauth2/introspect', 'token=foo').reply(200, {
        active: true
      })

      const h = new Hydra(Object.assign({scope: 'hydra.clients'}, config))
      return h.validateToken('foo').then((got) => {
        expect(got.active).toEqual(true)
      })
    })

    test('consent challenge verification and consent response signing should work when a valid key is provided', () => new Promise((resolve, reject) => {
      const keys = {
        "keys": [
          {
            "kty": "RSA",
            "kid": "private",
            "n": "wvHGUGrWUdGT3Eed5a_BVLe4Fj6RfVyYXgIOf0qrVdwJ8ibAqc6vUtjMXtZzyDOTQsb1UfrhVdNuMlBcGkvp2RdwNE1o6MPiPEgJE6bQKUM03yOiwlpdJsyeOK9QTMoCp8xdFf21r1ak5irvY0RRnPJm-dRmp5bB84nxulvEomDclVSw8CsWSERwvpTBsoJPjtKyYdm8xg--TDA408H8xzEt4KyimpaNaDrPJMJbz0REi-nOaDtLpEYJrw5avCMHOVAnSl3P_deUojSshRdNsLzPfAETKvjRqnPOzxFpaAisKDPuHRIl1_siC2pRr3dlJEFknbLtqfFhcfYb_XAqrvUDOaVWibYlhSrOKvI-ktgAw56P-09CiIGvVxHhGMDwyWU1D5QpLLCwwUq-a3atOwoe7p_rqNwe8QEOVf-x8cSs5KNwLstug9-kXyZe5IdC_WYOH2vH8tE1nZbNMINNu_fYdt-FJIMHBhZC8REzhIXm_TEq8KkBFiBpJ1zCB3uFLGDxD7wTw3cDSwL1FD_E8mkfpSoZkWfvwnGBo61pGHsBnTqroHhgf8UuIYgDlXCdU8mVuN5kjsQcGkgCuAdIvVtOXj5Pc-z0dc0_k-x7oYrfGEhJ8VkzimhLSwsU5kNDcMJ7KkDSaNq2gYQIMEM8Aq1SiW_7y1wkF0o8zTZ_Jik",
            "e": "AQAB",
            "d": "k6ebBPgXAvvRmawo_XrE3Y0WAss7WY-T3MiEAIgnBC5Y3i_aCAQDqaWKDl8ybTYbWR3nXEPA_0fYlIVnbYeIRSVKmGL1jjAoIG6TaW4VBtvfpQ-RzNGy8ptTUC4BjVgI8N2KuAhl37upxKhKj46EnnK_6oSliFRY7UTTccrmQfNJwFXYeuC3zN8B4mg72iB3b_9Im3LXV9E-2ug_cqzg8GLgk-dOdfaIfqTklrwb2_6iSLM74pje7zsZRJ2DvjJt20xJpjsuOd9atg1diqUe9DnekdcilI7IB-oVf6N5ihHfi8fhl-VSAqg1nh3WZyfw1KgvNH79IpYwr6ewhaK6wF1OMuix3DhVvVbMuoFvRBJsmiwNphce3DlFi2dhrbmMc2NagLKjInJLKECj3-F81Gr5J83D9-KTeZRV-0mLcdoaw-xPc8KuHMYwqR6Q_edmEhCf-tPguuik22sfXV7wWHTNr4D54xqMn2cx9Bp88ecw_6Ho1xgliN2M6ViHmvs6e29uBEubfHZbUChAlTPUwqInzhDdUkZiQb1ZstqkWKFSyafTDK1zWjAiuBFuHH4e7Khc_SFiGtmI_8ZHs8UKVClZ3BxSGofmjE2veazN2-lWQnz26-Xn_I6drANyOUCICVThPjNJZl_wganLyDU2sGp-8oesK2Yk3PuM4ept7t0",
            "p": "2ZmTVEsegqzYtZ-mJS2_xOoeIvGe1rVcsFxJUP7izjvF9xHxdHFYkSlfjpqQgSbtznYHypwg8LtMBsrxUKTtOMq60sV4mlUMbdxzlCt8YuzQUtVGb2XVGbcrE8tHdx8o5bAP1ISzVyr8e3ASItVh8b7BTFEIeazU8FOzPzbyggVBE_lmX7bZYm_c0AdSqKUnJ4085HT3KGN0UbiWkv7eGlmDy3g5I31r0bPtGPgxOxRJ4fN0-jmzn7vvSjCsi1XFACGGGj9SCNhMJVlnKhGhFVXDPlRiBnGTIF6QV8vl1W-Q72cNtIWBQ26w8POwXxR4MKDIEbq2OAthW3dZ3aGXow",
            "q": "5Vizr0dfPt57_L1CVsKKTBklBJctK4CrEl-zcLlr7s6rxL-T3jY0yxdqVpaZ4hqdK9RKaNhJgkxjwUiBjSDAoMG6tl-SBf73Y4TZSElnt49zLyH-WcxtrYK_hQpgQBdJnEnZyw9wXAD0CHMAXkzTS71h0ht8gczl1QYN-q-Pw5qr5JUo6ARQDiFpYmMPcmztp8PyUpc-nGAkpDHyw2_o76t2REC7hVgg32Kf-L81i5Y3cRTGHq9yhOTjRgZESt3_8bBgkHTpIrqPnPosOL0p5tMWMmPL5Vj3p4H7SffRartXkM4cqKWJ5H13rtA6Yx73ZYlX1m9RG5NOzSRDkaMXww"
          },
          {
            "kty": "RSA",
            "kid": "public",
            "n": "wvHGUGrWUdGT3Eed5a_BVLe4Fj6RfVyYXgIOf0qrVdwJ8ibAqc6vUtjMXtZzyDOTQsb1UfrhVdNuMlBcGkvp2RdwNE1o6MPiPEgJE6bQKUM03yOiwlpdJsyeOK9QTMoCp8xdFf21r1ak5irvY0RRnPJm-dRmp5bB84nxulvEomDclVSw8CsWSERwvpTBsoJPjtKyYdm8xg--TDA408H8xzEt4KyimpaNaDrPJMJbz0REi-nOaDtLpEYJrw5avCMHOVAnSl3P_deUojSshRdNsLzPfAETKvjRqnPOzxFpaAisKDPuHRIl1_siC2pRr3dlJEFknbLtqfFhcfYb_XAqrvUDOaVWibYlhSrOKvI-ktgAw56P-09CiIGvVxHhGMDwyWU1D5QpLLCwwUq-a3atOwoe7p_rqNwe8QEOVf-x8cSs5KNwLstug9-kXyZe5IdC_WYOH2vH8tE1nZbNMINNu_fYdt-FJIMHBhZC8REzhIXm_TEq8KkBFiBpJ1zCB3uFLGDxD7wTw3cDSwL1FD_E8mkfpSoZkWfvwnGBo61pGHsBnTqroHhgf8UuIYgDlXCdU8mVuN5kjsQcGkgCuAdIvVtOXj5Pc-z0dc0_k-x7oYrfGEhJ8VkzimhLSwsU5kNDcMJ7KkDSaNq2gYQIMEM8Aq1SiW_7y1wkF0o8zTZ_Jik",
            "e": "AQAB"
          }
        ]
      }

      const pem = jwkToPem(Object.assign({}, keys.keys[0], {
        dp: '',
        dq: '',
        qi: ''
      }), { private: true })

      nock('http://foo.localhost').get('/keys/hydra.consent.response/private').reply(200, { keys: [keys.keys[0]] })
      nock('http://foo.localhost').get('/keys/hydra.consent.challenge/public').reply(200, { keys: [keys.keys[1]] })

      const h = new Hydra(config)
      // const challenge = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZTNhOGI2YS1kMDExLTQ4MzctOTM0Ni02ZTVlMzhmYzY1OGEiLCJleHAiOjE0NzQ5ODYwMzIsImp0aSI6IjNjODdlNjgxLTdjNzctNDQwZS1iNGI0LTE1YTFmOTYzZDA3MyIsInJlZGlyIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9vYXV0aDIvYXV0aD9jbGllbnRfaWQ9YWUzYThiNmEtZDAxMS00ODM3LTkzNDYtNmU1ZTM4ZmM2NThhXHUwMDI2cmVkaXJlY3RfdXJpPWh0dHAlM0ElMkYlMkZsb2NhbGhvc3QlM0E0NDQ1JTJGY2FsbGJhY2tcdTAwMjZyZXNwb25zZV90eXBlPWNvZGVcdTAwMjZzY29wZT1oeWRyYStvZmZsaW5lK29wZW5pZFx1MDAyNnN0YXRlPXl4Z2RydnJvb2VnY3d1c3duaWd0cnducFx1MDAyNm5vbmNlPWl5ZndnbmtrbmRjbXBheGRtZWNpdWZtdiIsInNjcCI6WyJoeWRyYSIsIm9mZmxpbmUiLCJvcGVuaWQiXX0.WCMR50S_NSFxGDBAaMdaatF9025hzb8r0_OmMJgenou7uA5br5_B_KkonrwIljaVjAF4D4kmXpIAKKRy_Ip-smmdVPkgnZAUZMjzDbYNUnes3WdaD3vR9VTRXrB0rOdQZc1vQb-F5t2AA3obVpI3tGABdt0dr8OAg_H6d_dmprcBvOqv3yZTwrhlCRdk5apmvSSvcsdDvEhQixRYsEjeN6KmpqWVaBWet1QFCxG7DllKrmt4TzTJYoWWxd_w3Y7H1i3ZASJUx5M-s9KzvYnw6ShlOWIlwrfr5Zg5C8pCopHzhaeEKB26yqPyUC2FxuD0ncjhxa13qG8BqvMpQX43o4jIc3Ins6OmuQkpRqCqhqaHcgkZLSRkC6PWlLYz3ogeKy_WcmY4Y0fARnvbd5iRG6b_WfcAOz0aDl63BW99vVKi90fpYfOtg_jz5xRIg6BI8tR6WJcoDTh4KMQXGbD_gCV8ODrPTcydMgHFQUviKr0AUyg-EXq_J9Qm8_jn_SbCh6Dv1RPCUVQ3uD2ZELFPN12Ww3zYgX3Y5c46WygWxt5AEs2fc37rF6xnPpdqrRq89kvPVZoCJKXfY9XzFaK-kHyYUtbuLw8PVRVx018dle3lrmnDKlRi6IKY3dgdgoEKxKUazjJftO3NA6Y0Xi_510ArRcCrLf_e9CTBlyrZeHI'


      jwt.sign({
        "aud": "ae3a8b6a-d011-4837-9346-6e5e38fc658a",
        "exp": (Date.now() / 1000 | 0) + 360,
        "jti": "3c87e681-7c77-440e-b4b4-15a1f963d073",
        "redir": "https://localhost:8000/oauth2/auth?client_id=ae3a8b6a-d011-4837-9346-6e5e38fc658a&redirect_uri=http%3A%2F%2Flocalhost%3A4445%2Fcallback&response_type=code&scope=hydra+offline+openid&state=yxgdrvrooegcwuswnigtrwnp&nonce=iyfwgnkkndcmpaxdmeciufmv",
        "scp": [
          "hydra",
          "offline",
          "openid"
        ]
      }, pem, { algorithm: 'RS256' }, (error, challenge) => {
        if (error) {
          return reject(error)
        }

        h.generateConsentResponse(challenge, 'foobar', ['foo'], { bar: 'foo' }, { baz: 'foo' }).then((got) => {
          const resp = jwtDecode(got.consent)
          expect(resp.sub).toEqual('foobar')
          expect(resp.at_ext.bar).toEqual('foo')
          expect(resp.id_ext.baz).toEqual('foo')
          expect(resp.jti).toEqual('3c87e681-7c77-440e-b4b4-15a1f963d073')
          resolve()
        }).catch(reject)
      })
    }))
  })
})
