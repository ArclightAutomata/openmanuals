#!/usr/bin/env node
// Usage: om-doip-verify <aspe-uri> [profile-jws]
//   With a JWS argument (or on stdin) the profile is parsed locally; otherwise
//   it is fetched from the ASPE host named in the URI. Prints one JSON object:
//   {"fingerprint":..., "name":..., "claims":[{"uri","service","handle","verified","error"}]}
// Exit 0 on success (even when claims fail), 1 on a profile error.
import * as doip from 'doipjs'

const [uri, jwsArg] = process.argv.slice(2)
if (!uri || !/^aspe:[^:]+:[A-Za-z2-7]+$/.test(uri)) {
  console.error('usage: om-doip-verify <aspe-uri> [profile-jws]')
  process.exit(2)
}

async function readStdin() {
  if (process.stdin.isTTY) return ''
  let s = ''
  for await (const chunk of process.stdin) s += chunk
  return s.trim()
}

const timeoutMs = Number(process.env.OM_DOIP_TIMEOUT_MS || 20000)

async function main() {
  const jws = jwsArg || (await readStdin())
  const profile = jws ? await doip.asp.parseProfileJws(jws, uri) : await doip.asp.fetchASPE(uri)
  const persona = profile.personas[0]
  const claims = []
  for (const claim of persona.claims) {
    const out = { uri: claim.uri, service: null, handle: null, verified: false, error: null }
    try {
      claim.match()
      await Promise.race([
        claim.verify({ claims: { timeout: timeoutMs } }),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), timeoutMs + 1000)),
      ])
      const m = claim.matches && claim.matches[0]
      if (m) {
        out.service = m.about?.id || m.about?.name || null
        out.handle = m.profile?.display || null
      }
      out.verified = claim.status === doip.enums.ClaimStatus.VERIFIED || claim.verified === true
      if (!out.verified) {
        const name = Object.entries(doip.enums.ClaimStatus).find(([, v]) => v === claim.status)?.[0]
        out.error = name || String(claim.status)
      }
    } catch (e) {
      out.error = e && e.message ? e.message : String(e)
    }
    claims.push(out)
  }
  const fingerprint = profile.publicKey?.fingerprint || uri.split(':')[2]
  console.log(JSON.stringify({ fingerprint, name: persona.name, claims }))
}

main().catch((e) => {
  console.log(JSON.stringify({ error: e && e.message ? e.message : String(e) }))
  process.exit(1)
})
