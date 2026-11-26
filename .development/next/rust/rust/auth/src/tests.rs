use super::*;
use std::fs;
use tempfile::tempdir;

const MD5: &str = "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0";

#[test]
fn matches_legacy_go_crypt_vectors() {
    for (key, hash) in [
        ("password", MD5),
        ("password", "$apr1$deadbeef$NWLhx1Ai4ScyoaAboTFco."),
        ("missing salt", "$apr1$$EcorjwkoQz4mYcksVEk6j0"),
        ("abcdefgh", "$apr1$an overl$iroRZrWCEoQojCkf6p8LC0"),
        ("Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
        ("Hello world!", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"),
        ("Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
        ("Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."),
    ] {
        assert!(password::check_hash(key, hash));
        assert!(!password::check_hash("wrong", hash));
    }
    for invalid in [
        "",
        "x",
        "!",
        "!!",
        "*",
        "$7$salt$value",
        "$1$waytoolongsalt$hash",
        "$6$rounds=foo$x$v",
    ] {
        assert!(!password::check_hash("", invalid));
    }
}

#[test]
fn login_uses_router_layout_and_logout_revokes_session() {
    let root = tempdir().unwrap();
    let opt = root.path().join("opt/etc");
    let etc = root.path().join("etc");
    let data = root.path().join("data");
    fs::create_dir_all(&opt).unwrap();
    fs::create_dir_all(&etc).unwrap();
    fs::write(opt.join("shadow"), "demo:!:\n").unwrap();
    fs::write(etc.join("passwd"), format!("demo:{MD5}:0:0:\r\n")).unwrap();
    let auth = Auth::open(&data, root.path(), false).unwrap();
    assert!(auth.enabled());
    assert!(auth.allows("/api/auth/login", ""));
    assert!(auth.allows("/api/auth/status", ""));
    assert!(auth.allows("/assets/main.js", ""));
    for p in [
        "/api/auth/logout",
        "/api/auth/config",
        "/api/auth/status/",
        "/api/lists",
    ] {
        assert!(!auth.allows(p, ""));
    }
    assert!(auth.login("demo", "wrong").unwrap().is_none());
    assert!(auth.login("demo:!", "password").unwrap().is_none());
    let token = auth.login("demo", "password").unwrap().unwrap();
    assert!(token.len() == 48 && token.bytes().all(|c| c.is_ascii_hexdigit()));
    let header = format!("other=1; n2s_sess=\"{token}\"; test=1");
    assert_eq!(session_token(&header), token);
    assert!(login_cookie(&token).contains("Max-Age=604800; HttpOnly; SameSite=Lax"));
    assert!(auth.allows("/api/lists", session_token(&header)));
    auth.logout(&token);
    assert!(!auth.valid_session(&token));
    fs::write(etc.join("openwrt_release"), "").unwrap();
    fs::write(opt.join("shadow"), format!("only-opt:{MD5}:x")).unwrap();
    let openwrt = Auth::open(&data, root.path(), false).unwrap();
    assert!(openwrt.login("only-opt", "password").unwrap().is_none());
}

#[test]
fn preserves_other_settings_and_only_applies_committed_toggles() {
    let root = tempdir().unwrap();
    let path = root.path().join(SETTINGS);
    fs::write(&path, r#"{"logging_disabled":true,"unknown":[1,2]}"#).unwrap();
    let auth = Auth::open(root.path(), root.path(), false).unwrap();
    auth.set_enabled(false).unwrap();
    let stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        stored,
        serde_json::json!({"logging_disabled":true,"unknown":[1,2],"auth_enabled":false})
    );
    let auth = Auth::open(root.path(), root.path(), false).unwrap();
    assert!(!auth.enabled());
    auth.set_enabled(true).unwrap();
    let recovery = Auth::open(root.path(), root.path(), true).unwrap();
    assert!(recovery.forced_off() && !recovery.enabled());
    recovery.set_enabled(false).unwrap();
    assert!(Auth::open(root.path(), root.path(), false)
        .unwrap()
        .enabled());
    fs::write(&path, "broken").unwrap();
    assert!(auth.set_enabled(false).is_err());
    assert!(auth.enabled());
    assert_eq!(fs::read_to_string(path).unwrap(), "broken");
    assert!(Auth::open(root.path(), root.path(), false).is_err());
}

#[test]
fn sessions_expire_and_concurrent_issuance_is_unique() {
    let expired = Sessions::new(Duration::ZERO);
    assert!(!expired.valid(&expired.issue().unwrap()));
    let sessions = Sessions::new(Duration::from_secs(1));
    let tokens = std::thread::scope(|s| {
        (0..32)
            .map(|_| s.spawn(|| sessions.issue().unwrap()))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<std::collections::HashSet<_>>()
    });
    assert_eq!(tokens.len(), 32);
    for token in tokens {
        assert!(sessions.valid(&token));
        sessions.remove(&token);
        assert!(!sessions.valid(&token));
    }
}
