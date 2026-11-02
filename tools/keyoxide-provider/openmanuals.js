/*
Copyright 2026 OpenManuals contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
 * OpenManuals service provider
 * @module serviceProviders/openmanuals
 * @example
 * import { ServiceProviderDefinitions } from 'doipjs';
 * const sp = ServiceProviderDefinitions.data.openmanuals.processURI('https://openmanuals.win/k/QPRGVPJNWDXH4ESK2RYDTZJLTE');
 */

// Proposed for doipjs's src/serviceProviders/ (with an entry in index.js).
// An OpenManuals key is an Ariadne Signature Profile key; the proof is the
// claims list of that key's signed profile, which must contain the Keyoxide
// profile's fingerprint URI (openpgp4fpr:… or aspe:…).

import * as E from '../enums.js'
import { ServiceProvider } from '../serviceProvider.js'

export const reURI = /^https:\/\/openmanuals\.org\/k\/([a-zA-Z2-7]{26})\/?$/

/**
 * @function
 * @param {string} uri - Claim URI to process
 * @returns {ServiceProvider} The service provider information based on the claim URI
 */
export function processURI (uri) {
  const match = uri.match(reURI)
  const fingerprint = match[1].toUpperCase()

  return new ServiceProvider({
    about: {
      id: 'openmanuals',
      name: 'OpenManuals',
      homepage: 'https://openmanuals.win'
    },
    profile: {
      display: fingerprint,
      uri: `https://openmanuals.win/k/${fingerprint}`,
      qr: null
    },
    claim: {
      uriRegularExpression: reURI.toString(),
      uriIsAmbiguous: false
    },
    proof: {
      request: {
        uri: `https://openmanuals.win/k/${fingerprint}`,
        fetcher: E.Fetcher.HTTP,
        accessRestriction: E.ProofAccessRestriction.NONE,
        data: {
          url: `https://openmanuals.win/api/key/${fingerprint}`,
          format: E.ProofFormat.JSON
        }
      },
      response: {
        format: E.ProofFormat.JSON
      },
      target: [{
        format: E.ClaimFormat.URI,
        encoding: E.EntityEncodingFormat.PLAIN,
        relation: E.ClaimRelation.CONTAINS,
        path: ['claims']
      }]
    }
  })
}

export const functions = {
  // Runs only after the proof was found: show the key's profile name, the
  // way other providers show a handle. An unverified claim keeps showing the
  // fingerprint, so nobody can borrow a name by claiming someone else's key.
  validate: async (/** @type {ServiceProvider} */ claimData, proofData, verificationResult, opts) => {
    const name = proofData.result && proofData.result.name
    if (typeof name === 'string' && name.length > 0) {
      claimData.profile.display = name
    }
    return true
  }
}

export const tests = [
  {
    uri: 'https://openmanuals.win/k/QPRGVPJNWDXH4ESK2RYDTZJLTE',
    shouldMatch: true
  },
  {
    uri: 'https://openmanuals.win/k/qprgvpjnwdxh4esk2rydtzjlte/',
    shouldMatch: true
  },
  {
    uri: 'https://openmanuals.win/k/QPRGVPJNWDXH4ESK2RYDTZJLTE/extra',
    shouldMatch: false
  },
  {
    uri: 'https://openmanuals.win/manual/01ARZ3NDEKTSV4RRFFQ69G5FAV',
    shouldMatch: false
  },
  {
    uri: 'https://example.org/k/QPRGVPJNWDXH4ESK2RYDTZJLTE',
    shouldMatch: false
  }
]
