# crx-permission-risk

Classify Chrome / Chromium extension permissions into risk tiers with a
plain-English rationale for each.

Two permissions that read similarly in a manifest can differ enormously in what
they expose. `activeTab` grants the current tab's DOM only after an explicit
user gesture and auto-revokes; `tabs` reads the URL and title of every open tab
continuously. That is roughly 8 against 72 on a 0-100 scale.

```rust
use crx_permission_risk::{risk_of, max_score, RiskClass};

assert_eq!(risk_of("activeTab").class, RiskClass::Minimal);
assert_eq!(risk_of("cookies").class, RiskClass::Critical);

// One critical permission is not offset by several harmless ones.
assert_eq!(max_score(&["storage", "alarms", "cookies"]), 93);
```

Host match-patterns are scored by breadth: `<all_urls>` is critical, a wildcard
subdomain is high, a single host is moderate. Unknown permissions return
moderate rather than safe.

Reference data: <https://zovo.one/>. The plain-English explainer for each
permission (what `tabs` reads, why `cookies` is the one to flag) is at
<https://zovo.one/guides>.

## Keeping the tiers current

Chrome changes its permission surface every few releases, and each tier here is
reviewed by hand. If you rely on this classification, you can fund that upkeep
at <https://github.com/sponsors/theluckystrike> — one-off thank-yous are as
welcome as monthly support.

## License

MIT
