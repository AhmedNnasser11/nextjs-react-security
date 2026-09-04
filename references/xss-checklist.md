# XSS

Trace every attacker-influenced value to its final browser context. React escaping is
helpful only when values remain ordinary text nodes.

## Dangerous sinks

- Review `dangerouslySetInnerHTML`, HTML serializers, markdown renderers, template
  interpolation, `style` values, URL attributes, and inline scripts.
- For JSON-LD, escape `<`, `>`, and `&` after JSON serialization so strings cannot close
  the script element.
- For `href`, `src`, `action`, and redirects, validate the scheme and destination at the
  sink; reject `javascript:`, `vbscript:`, unsafe `data:`, protocol-relative URLs, and
  unexpected hosts.

## Sanitization

- Use a maintained sanitizer with an explicit tag, attribute, style, and URI-scheme
  allowlist. Do not trust sanitizer defaults without checking the installed version docs.
- Keep sanitization context-specific. HTML sanitization does not make shell arguments,
  SQL fragments, CSS, or HTTP headers safe.
- Test encoded entities, mixed case, whitespace/control characters, malformed markup,
  SVG/MathML, event attributes, and mutation/parser differentials.

## Decision gate

Report `CONFIRMED` only when the value reaches an executable browser context without an
effective mitigation and has meaningful impact. Otherwise report `HARDENING` or
`POTENTIAL` with the exact missing boundary.
