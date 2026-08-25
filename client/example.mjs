// Manual live probe: exercise the ODoH client against the real target,
// directly and through each public relay. Not part of the suite (the suite's
// odoh live test uses the default transport); this is the diagnostic tool.
import { OdohTransport } from './odoh.js'
import { buildQuery, parseAnswers, TYPES } from './dns-query.js'

const wire = buildQuery('14898', TYPES.A, 0)
const routes = [
  ['DIRECT to target', ['https://odoh.hns.one/dns-query']],
  ['relay edgecompute', ['https://odoh-relay.edgecompute.app/']],
  ['relay numa', ['https://odoh-relay.numa.rs/relay']]
]
for (const [label, relays] of routes) {
  const t = new OdohTransport({ target: 'odoh.hns.one', relays })
  try {
    const start = Date.now()
    const { answer, via } = await t.query(wire)
    const parsed = parseAnswers(Buffer.from(answer))
    console.log(`${label}: OK via ${via} in ${Date.now() - start}ms — rcode ${parsed.rcode}, ${parsed.answers.length} answers`,
      parsed.answers[0] ? JSON.stringify(parsed.answers[0]).slice(0, 80) : '')
  } catch (err) {
    console.log(`${label}: FAIL — ${err.message || err}`)
  }
}
