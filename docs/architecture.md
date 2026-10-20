# Architecture and security boundary

`Core` has no ASP.NET or MCP dependency. `AuthorizationPolicy` holds a frozen map of exact ordinal tool names to immutable role sets. Its inputs are a typed `AuthorizationContext` containing a validated subject, role, tool name and JSON arguments. Its outputs are an allow flag and a stable reason code. The API authenticates the subject and role before constructing that context. No role from an HTTP header or request body is used.

| Tool | viewer | operator | admin |
| --- | --- | --- | --- |
| `crm.get_customer` | allow | allow | allow |
| `crm.list_orders` | allow | allow | allow |
| `crm.update_order` | deny | allow if amount ≤ 1000 | allow if amount ≤ 1000 |
| `crm.delete_customer` | deny | deny | allow |
| `crm.export_customers` | deny | deny | allow |

`crm.update_order` requires a nonnegative JSON number named `amount` representable as decimal. Missing, malformed and excessive amounts deny. Unknown tool names deny. The amount threshold is a demo policy constant, not a production business rule.

The API validates signature, HS256 algorithm, exact issuer and audience, expiration with zero clock skew, and exactly one nonblank subject and valid role. The signing key must be supplied externally and startup fails without it. The unauthenticated demo token issuer is registered only in Development; the API refuses the demo issuer outside Development. Development deployments must stay on loopback; environment labels alone are not an access boundary. Production requires a distinct configured issuer and key but has no issuer or identity management endpoint. Deployment authentication, key rotation and trusted identity provider integration remain future work.

The evaluation endpoint returns only the decision and reason code. It performs no MCP call, CRM operation, forwarding or audit persistence. Consequently, it offers no zero-upstream-invocation guarantee. Its decision is illustrative until the next milestone integrates enforcement at the MCP gateway. It must not be used as a stand-alone check followed by an unrelated tool call. Arguments and tokens are not included in decision responses or application-authored logs. The demo token issuance response necessarily contains the token.

This milestone was informed by MCP Sentinel's default-deny and exact-name policy patterns without copying its gateway.
