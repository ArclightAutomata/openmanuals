// Tests the proposed doipjs provider against the doipjs that tools/doip-verify
// installs, without network: URI matching (the provider's own `tests`, with
// doipjs's other providers present) and the proof check on a /api/key response.
// Run: node tools/keyoxide-provider/test.mjs   (after npm ci in tools/doip-verify)
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const src = path.join(here, '../doip-verify/node_modules/doipjs/src')
const doip = await import(pathToFileURL(path.join(src, 'index.js')))

// Load the provider as if it sat in doipjs's src/serviceProviders/.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'om-provider-'))
const code = fs.readFileSync(path.join(here, 'openmanuals.js'), 'utf8')
  .replace("'../enums.js'", JSON.stringify(pathToFileURL(path.join(src, 'enums.js')).href))
  .replace("'../serviceProvider.js'", JSON.stringify(pathToFileURL(path.join(src, 'serviceProvider.js')).href))
fs.writeFileSync(path.join(tmp, 'openmanuals.mjs'), code)
const om = await import(pathToFileURL(path.join(tmp, 'openmanuals.mjs')))
fs.rmSync(tmp, { recursive: true })
doip.ServiceProviderDefinitions.data.openmanuals = om
doip.ServiceProviderDefinitions.list.push('openmanuals')

const FP = 'QPRGVPJNWDXH4ESK2RYDTZJLTE'
const KEYOXIDE = 'aspe:keyoxide.org:6WJK26YKF6WUVPIZTS2I2BIT64'

for (const t of om.tests) {
  const c = new doip.Claim(t.uri, KEYOXIDE)
  c.match()
  const ids = c.matches.map((m) => m.about.id)
  if (t.shouldMatch) {
    assert.deepEqual(ids, ['openmanuals'], `${t.uri} should match only openmanuals (got ${ids})`)
    assert.equal(c.isAmbiguous(), false)
  } else {
    assert.ok(!ids.includes('openmanuals'), `${t.uri} should not match openmanuals`)
  }
}

// The proof: GET /api/key/<fp> lists the Keyoxide identity in `claims`.
const sp = om.processURI(`https://openmanuals.win/k/${FP.toLowerCase()}`)
assert.equal(sp.proof.request.data.url, `https://openmanuals.win/api/key/${FP}`)
const response = { fingerprint: FP, name: 'Alice', claims: ['https://gist.github.com/alice/1', KEYOXIDE] }
let r = await doip.verifications.run(response, sp, KEYOXIDE)
assert.equal(r.result, true, JSON.stringify(r))
r = await doip.verifications.run(response, sp, 'openpgp4fpr:3637202523E7C1309AB79E99EF2DC5827B445F4B')
assert.equal(r.result, false, 'a fingerprint the key does not list must not verify')
r = await doip.verifications.run({ ...response, claims: [] }, sp, KEYOXIDE)
assert.equal(r.result, false)

// After a verified proof the claim shows the profile name.
assert.equal(sp.profile.display, FP)
assert.equal(await om.functions.validate(sp, { result: response }, { result: true }, {}), true)
assert.equal(sp.profile.display, 'Alice')

console.log(`ok: ${om.tests.length} URI cases, proof check`)
