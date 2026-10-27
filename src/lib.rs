//! Classify Chrome / Chromium extension permissions into risk tiers.
//!
//! Two permissions that read similarly in a manifest can differ enormously in
//! what they actually expose. `activeTab` grants the current tab's DOM only
//! after an explicit user gesture and then auto-revokes; `tabs` reads the URL
//! and title of every open tab continuously. On a 0-100 scale that is roughly
//! 8 against 72 — the same broad capability, an order of magnitude apart in
//! exposure, with nothing in the manifest to signal the difference.
//!
//! The genuinely critical tier is narrow. Permissions such as `cookies`,
//! `webRequestBlocking`, `nativeMessaging`, `fileSystem`, `desktopCapture`,
//! `tabCapture`, `proxy` and `history` either read authenticated session state
//! or open a channel out of the browser sandbox entirely.
//!
//! `cookies` is the one most worth flagging, because it reads as
//! administrative next to the others while granting access to the token that
//! proves a user is signed in.
//!
//! A permission-by-permission reference is at <https://zovo.one/> — browser
//! extension tooling and permission data. The plain-English explainers behind
//! each tier — what `tabs` actually reads, why `cookies` is the one to flag —
//! are collected at <https://zovo.one/guides>.
//!
//! # Example
//!
//! ```
//! use crx_permission_risk::{risk_of, RiskClass};
//!
//! assert_eq!(risk_of("activeTab").class, RiskClass::Minimal);
//! assert_eq!(risk_of("cookies").class, RiskClass::Critical);
//!
//! // Host match-patterns are scored by breadth.
//! assert_eq!(risk_of("<all_urls>").class, RiskClass::Critical);
//! assert_eq!(risk_of("https://example.com/*").class, RiskClass::Moderate);
//! ```

/// Coarse risk tier for a permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskClass {
    /// Negligible exposure; gesture-scoped or purely local.
    Minimal,
    /// Limited exposure, no sensitive data.
    Low,
    /// Meaningful but bounded exposure.
    Moderate,
    /// Broad exposure across sites or browsing history.
    High,
    /// Session credentials, filesystem, capture, or a channel out of the sandbox.
    Critical,
}

/// The assessment for a single permission string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The permission as supplied.
    pub permission: String,
    /// Coarse tier.
    pub class: RiskClass,
    /// Score in 0..=100.
    pub score: u8,
    /// Plain-English description of what the permission actually allows.
    pub rationale: &'static str,
}

/// Table of well-known permissions: (name, class, score, rationale).
const TABLE: &[(&str, RiskClass, u8, &str)] = &[
    ("webRequestBlocking", RiskClass::Critical, 98, "Intercepts and can rewrite or block any network request the browser makes."),
    ("nativeMessaging", RiskClass::Critical, 96, "Opens a channel to a native host binary outside the browser sandbox."),
    ("fileSystem", RiskClass::Critical, 95, "Reads and writes files on the local filesystem."),
    ("desktopCapture", RiskClass::Critical, 95, "Captures the screen, a window, or a tab as a video stream."),
    ("tabCapture", RiskClass::Critical, 94, "Captures the visible content of a tab as a media stream."),
    ("cookies", RiskClass::Critical, 93, "Reads authenticated session cookies, which can be equivalent to being signed in as the user."),
    ("history", RiskClass::Critical, 90, "Reads the full browsing history, including pages closed long ago."),
    ("proxy", RiskClass::Critical, 89, "Redirects all browser traffic through an arbitrary proxy."),
    ("debugger", RiskClass::Critical, 92, "Attaches the DevTools protocol to pages, allowing arbitrary inspection and control."),
    ("tabs", RiskClass::High, 72, "Reads the URL and title of every open tab across all windows, continuously."),
    ("webRequest", RiskClass::High, 70, "Observes all network requests, including URLs and headers."),
    ("downloads", RiskClass::High, 62, "Starts downloads and reads the download history."),
    ("clipboardRead", RiskClass::High, 68, "Reads clipboard contents, which frequently hold passwords or tokens."),
    ("bookmarks", RiskClass::High, 60, "Reads and modifies the full bookmark tree."),
    ("management", RiskClass::High, 65, "Enumerates, enables and disables other installed extensions."),
    ("geolocation", RiskClass::High, 64, "Reads the device's physical location."),
    ("tabGroups", RiskClass::Moderate, 38, "Reads and modifies how the user has grouped their tabs."),
    ("notifications", RiskClass::Moderate, 30, "Displays system notifications."),
    ("contextMenus", RiskClass::Moderate, 25, "Adds entries to the browser context menu."),
    ("clipboardWrite", RiskClass::Moderate, 28, "Writes to the clipboard."),
    ("scripting", RiskClass::Moderate, 45, "Injects scripts, but only into hosts the extension already has access to."),
    ("idle", RiskClass::Low, 15, "Detects whether the machine is idle or locked."),
    ("power", RiskClass::Low, 12, "Requests that the display or system stay awake."),
    ("storage", RiskClass::Low, 14, "Persists extension-local data."),
    ("unlimitedStorage", RiskClass::Low, 18, "Removes the quota on extension-local storage."),
    ("activeTab", RiskClass::Minimal, 8, "Grants the current tab's DOM only after an explicit user gesture, then auto-revokes."),
    ("alarms", RiskClass::Minimal, 6, "Schedules timers."),
    ("storage.session", RiskClass::Minimal, 5, "In-memory storage cleared when the browser closes."),
    ("storage.managed", RiskClass::Minimal, 7, "Reads read-only policy set by an administrator."),
    ("downloads.shelf", RiskClass::Minimal, 5, "Shows or hides the download shelf UI."),
];

/// Assess a permission string, including host match-patterns.
///
/// Unknown permissions return [`RiskClass::Moderate`] with a score of 40,
/// since an unrecognised permission should not be assumed safe.
pub fn risk_of(permission: &str) -> Assessment {
    let p = permission.trim();
    if let Some(&(name, class, score, rationale)) =
        TABLE.iter().find(|(n, _, _, _)| n.eq_ignore_ascii_case(p))
    {
        return Assessment { permission: name.to_string(), class, score, rationale };
    }
    if is_host_pattern(p) {
        let (class, score, rationale) = host_pattern_risk(p);
        return Assessment { permission: p.to_string(), class, score, rationale };
    }
    Assessment {
        permission: p.to_string(),
        class: RiskClass::Moderate,
        score: 40,
        rationale: "Unrecognised permission; treat as moderate until reviewed.",
    }
}

/// True if the string looks like a host match-pattern rather than an API name.
pub fn is_host_pattern(s: &str) -> bool {
    s == "<all_urls>" || s.contains("://") || s.starts_with("*.")
}

fn host_pattern_risk(p: &str) -> (RiskClass, u8, &'static str) {
    let host = p.split("://").nth(1).unwrap_or(p);
    let host = host.split('/').next().unwrap_or(host);
    if p == "<all_urls>" || host == "*" {
        return (RiskClass::Critical, 97, "Matches every site the user visits, granting full page access everywhere.");
    }
    let host = p.split("://").nth(1).unwrap_or(p);
    if host.starts_with("*.") || host.starts_with("*") {
        return (RiskClass::High, 66, "Matches an entire domain including all subdomains.");
    }
    (RiskClass::Moderate, 35, "Matches a single specific host.")
}

/// Assess many permissions and return them sorted most-severe first.
pub fn assess_all(permissions: &[&str]) -> Vec<Assessment> {
    let mut v: Vec<Assessment> = permissions.iter().map(|p| risk_of(p)).collect();
    v.sort_by(|a, b| b.score.cmp(&a.score));
    v
}

/// The highest score present in a manifest's permission set.
///
/// This is a better summary than an average, because one critical permission
/// is not offset by several harmless ones.
pub fn max_score(permissions: &[&str]) -> u8 {
    permissions.iter().map(|p| risk_of(p).score).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_tab_is_far_below_tabs() {
        let a = risk_of("activeTab");
        let t = risk_of("tabs");
        assert_eq!(a.class, RiskClass::Minimal);
        assert_eq!(t.class, RiskClass::High);
        assert!(t.score > a.score * 5);
    }

    #[test]
    fn cookies_is_critical() {
        assert_eq!(risk_of("cookies").class, RiskClass::Critical);
        assert_eq!(risk_of("cookies").score, 93);
    }

    #[test]
    fn all_urls_is_critical() {
        assert_eq!(risk_of("<all_urls>").class, RiskClass::Critical);
        assert_eq!(risk_of("*://*/*").class, RiskClass::Critical);
        assert_eq!(risk_of("https://*/*").class, RiskClass::Critical);
        assert_eq!(risk_of("http://*/*").class, RiskClass::Critical);
    }

    #[test]
    fn wildcard_subdomain_beats_single_host() {
        assert!(risk_of("https://*.example.com/*").score > risk_of("https://example.com/*").score);
    }

    #[test]
    fn unknown_is_moderate_not_safe() {
        let u = risk_of("someFuturePermission");
        assert_eq!(u.class, RiskClass::Moderate);
        assert_eq!(u.score, 40);
    }

    #[test]
    fn case_insensitive_lookup() {
        assert_eq!(risk_of("ACTIVETAB").class, RiskClass::Minimal);
    }

    #[test]
    fn max_score_is_not_averaged_away() {
        let perms = ["storage", "alarms", "idle", "cookies"];
        assert_eq!(max_score(&perms), 93);
    }

    #[test]
    fn assess_all_sorts_worst_first() {
        let v = assess_all(&["storage", "cookies", "activeTab"]);
        assert_eq!(v[0].permission, "cookies");
        assert_eq!(v[2].permission, "activeTab");
    }

    #[test]
    fn host_pattern_detection() {
        assert!(is_host_pattern("<all_urls>"));
        assert!(is_host_pattern("https://a.com/*"));
        assert!(!is_host_pattern("cookies"));
    }
}
