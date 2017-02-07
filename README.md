# hydra-js

[![Join the chat at https://gitter.im/ory/hydra](https://img.shields.io/badge/join-chat-00cc99.svg)](https://gitter.im/ory/hydra?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Join mailinglist](https://img.shields.io/badge/join-mailinglist-00cc99.svg)](https://groups.google.com/forum/#!forum/ory-hydra/new)
[![Join newsletter](https://img.shields.io/badge/join-newsletter-00cc99.svg)](http://eepurl.com/bKT3N9)

[Hydra](https://github.com/ory/hydra) is a runnable server implementation of the OAuth2 2.0 authorization framework and the OpenID Connect Core 1.0.

Hydra-js is a client library for javascript. It is currently available as an npm-module only. At this moment, Hydra-js
primarily helps you with performing the consent validation.
We welcome contributions that implement more of the Hydra HTTP REST API.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [hydra-js](#hydra-js)
  - [Installation](#installation)
  - [Examples](#examples)
    - [Getting an access token with the client_credentials flow](#getting-an-access-token-with-the-client_credentials-flow)
    - [Consent flow](#consent-flow)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installation

```bash
$ npm i --save hydra-js
```

## Examples

### Instantiating

```js
var Hydra = require('hydra-js')

const config = {
 client: {
   id: process.env.HYDRA_CLIENT_ID, // id of the client you want to use, defaults to this env var
   secret: process.env.HYDRA_CLIENT_SECRET, // secret of the client you want to use, defaults to this env var
 },
 auth: {
   tokenHost: process.env.HYDRA_URL, // hydra url, defaults to this env var
 }
}

const hydra = new Hydra(config)
```

### Getting an access token with the client_credentials flow

```js
var Hydra = require('hydra-js')

const hydra = new Hydra(/* options */)
hydra.authenticate().then((token) => {
  // ...
}).catch((error) => {
  // ...
})
```

### Consent flow

The following examples fetches the appropriate cryptographic keys and access tokens automatically, you basically need to do:

```js
var Hydra = require('hydra-js')

const hydra = new Hydra(/* options */)

// verify consent challenge
hydra.verifyConsentChallenge(challenge).then(({ challenge: data }) => {
  // consent challenge is valid, render the consent screen:
  //  w.render('consent', { data })
}).catch((error) => {
  // error
})

// generate consent challenge
hydra.generateConsentResponse(challenge, subject, scopes, {}, data).then(({ consent }) => {
  // success! redirect back to hydra:
  //  w.redirect(challenge.redir + '&consent=' + consent)
}).catch((error) => {
  // error
})
```