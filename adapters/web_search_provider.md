# External Web Search Provider Contract

## Purpose

Provide the agent with a real external search capability for security discovery and corroboration.

The Skill MUST NOT silently substitute memory for live search when freshness is required.

## Provider

The reference deployment may bind this contract to Exa/Web Search or another approved provider.
The provider-specific API schema MUST come from the provider's current official documentation; do not invent endpoints or request fields in the Skill.

## Required operations

### search

Input:

```json
{
  "query": "...",
  "domains": ["..."],
  "freshness": "live|recent|any",
  "num_results": 5
}
```

Output:

```json
{
  "provider": "...",
  "query": "...",
  "retrieved_at": "...",
  "results": [
    {
      "title": "...",
      "url": "https://...",
      "published_at": null,
      "updated_at": null,
      "snippet": "..."
    }
  ],
  "failure": null
}
```

### open

Every result used as evidence SHOULD be opened through an approved URL-fetch gateway such as `scripts/open_url.py` before it is cited as substantive evidence.

Search snippets are discovery signals, not confirmed security evidence.

## Domain policy

Prefer domain-restricted searches against:

- nextjs.org / vercel.com
- react.dev
- nodejs.org
- github.com
- osv.dev / api.osv.dev
- npmjs.com
- owasp.org
- portswigger.net
- cve.org / nvd.nist.gov
- socket.dev when supply-chain intelligence is required

Unknown domains require explicit justification and secondary-source status.
