use super::*;
use crate::matrix::{probe_hop, ProbeLane};
use base64ct::{Base64, Encoding};
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicU32, Arc},
    thread,
    time::Duration,
};

#[test]
fn legacy_redirects_resolve_relative_https_and_reject_new_authorities() {
    let base = "https://origin.test/dir/nested/page?old=1".parse().unwrap();
    for (location, expected) in [
        (
            "../data/%2F?x=%2E#ignored",
            "https://origin.test/dir/data/%2F?x=%2E",
        ),
        ("?next=1", "https://origin.test/dir/nested/page?next=1"),
        ("#anchor", "https://origin.test/dir/nested/page?old=1"),
        ("//ORIGIN.test:443/done", "https://origin.test/done"),
        ("https://origin.test./a/..", "https://origin.test/"),
        ("/dir/.//page", "https://origin.test/dir//page"),
        ("./%2e/part", "https://origin.test/dir/nested/%2e/part"),
    ] {
        assert_eq!(same_authority(&base, location).unwrap(), expected);
    }
    for location in [
        "http://origin.test/",
        "https://another.test/",
        "//another.test/done",
        "https://origin.test:444/",
        "https://origin.test:65536/",
        "https://origin.test:wrong/",
        "//user@origin.test/done",
        "https:/origin.test/done",
        "/bad%xx",
        "/two words",
        "//origin.test\\@another.test/done",
    ] {
        assert!(same_authority(&base, location).is_err(), "{location}");
    }
}

#[test]
fn legacy_redirect_headers_take_first_location_after_informational_blocks() {
    assert!(matches!(
        header("HTTP/2 302\r\nLocation: /pending\r\n").unwrap(),
        Header::Pending
    ));
    for code in [301, 302, 303, 307, 308] {
        let raw = format!("HTTP/1.1 103 Early Hints\r\nLocation: https://wrong.test/\r\n\r\nHTTP/2 {code}\r\nlOcAtIoN: /first\r\nLocation: /later\r\n\r\n");
        assert!(matches!(header(&raw).unwrap(), Header::Redirect(value) if value == "/first"));
    }
    assert!(matches!(
        header("HTTP/2 300\r\nLocation: /not-followed\r\n\r\n").unwrap(),
        Header::Terminal
    ));
    assert!(matches!(
        header("HTTP/2 302\r\nLocation: \t\r\nLocation: /later\r\n\r\n").unwrap(),
        Header::Terminal
    ));
    assert!(header(&format!(
        "HTTP/2 302\r\nLocation: /{}\r\n\r\n",
        "x".repeat(MAX_LOCATION)
    ))
    .is_err());
}

#[test]
fn legacy_redirect_chain_needs_evidence_for_every_hop_and_does_not_count_redirect_body() {
    let started = Instant::now();
    let control = Control::new(1, true);
    let uri: Uri = "https://origin.test/".parse().unwrap();
    for stop_at in [1, 2, 3] {
        let mut attempts = 0;
        let result = follow(
            "origin.test",
            uri.clone(),
            started,
            started + Duration::from_secs(1),
            10,
            &control,
            |hop| {
                attempts += 1;
                let output = if attempts < 3 {
                    Output::Redirect(format!("/hop{attempts}"))
                } else {
                    Output::Terminal(
                        json!({"host":"origin.test","ok":true,"code":200,"size":65536,"ttfb_ms":1}),
                    )
                };
                if attempts != 1 {
                    assert_eq!(hop.uri.path(), format!("/hop{}", attempts - 1));
                }
                Ok(Some(attest(
                    output,
                    "origin.test",
                    30,
                    Ok(if attempts == stop_at { 30 } else { 31 }),
                )))
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(attempts, stop_at);
        assert_eq!(result["ok"], false);
        assert!(result["err"].as_str().unwrap().contains("NFQUEUE"));
        assert_eq!(result["size"], if attempts < 3 { 0 } else { 65536 });
    }
}

#[test]
fn legacy_redirect_chain_stops_before_requesting_other_origins_or_ports() {
    let control = Control::new(1, true);
    for destination in [
        "https://different.test/rejected-path",
        "https://origin.test:8443/rejected-path",
        "http://origin.test/rejected-path",
    ] {
        let start = Instant::now();
        let mut requests = 0;
        let result = follow(
            "origin.test",
            "https://origin.test/".parse().unwrap(),
            start,
            start + Duration::from_secs(1),
            10,
            &control,
            |hop| {
                assert_eq!(hop.uri, &"https://origin.test/".parse::<Uri>().unwrap());
                requests += 1;
                Ok(Some(attest(
                    Output::Redirect(destination.into()),
                    "origin.test",
                    30,
                    Ok(31),
                )))
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(requests, 1);
        assert_eq!(result["ok"], false);
        assert_eq!(result["code"], 0);
        assert!(!result.to_string().contains("rejected-path"));
    }
}

#[test]
fn public_redirects_pin_only_the_new_authority_and_keep_one_deadline() {
    let control = Control::new(1, true);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(1);
    let selected: Ipv4Addr = "93.184.216.34".parse().unwrap();
    let new: Ipv4Addr = "93.184.216.35".parse().unwrap();
    let mut asked = Vec::new();
    let mut requested = Vec::new();
    let report = follow_public(
        "old.test",
        "https://old.test/".parse().unwrap(),
        Chain {
            lease: start..deadline,
            port_count: 5,
            baseline: false,
            address: Some(selected),
            local_ips: &[],
        },
        &control,
        |host, end| {
            assert_eq!(end, deadline);
            asked.push(host.to_owned());
            Ok(new)
        },
        |hop| {
            assert_eq!(hop.deadline, deadline);
            assert_eq!(hop.redirected, !requested.is_empty());
            requested.push((hop.uri.to_string(), hop.address));
            Ok(Some(match requested.len() {
                1 => Output::Redirect("https://cdn.fixture.net:443/next?query=%2F#fragment".into()),
                2 => Output::Redirect("final".into()),
                _ => Output::Terminal(json!({"host":"old.test","ok":true,"code":200,"size":33000})),
            }))
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(asked, ["cdn.fixture.net"]);
    assert_eq!(
        requested,
        [
            ("https://old.test/".into(), Some(selected)),
            ("https://cdn.fixture.net/next?query=%2F".into(), Some(new)),
            ("https://cdn.fixture.net/final".into(), Some(new)),
        ]
    );
    assert_eq!(report["host"], "old.test");
    assert_eq!(report["ok"], true);
}

#[test]
fn public_redirects_refuse_private_literal_dns_and_interface_addresses_before_http() {
    for (location, lookup_ip, locals, expected_lookups) in [
        ("https://127.0.0.1/", "93.184.216.34", None, 0),
        ("https://192.168.1.1/", "93.184.216.34", None, 0),
        ("https://100.64.1.1/", "93.184.216.34", None, 0),
        ("https://192.0.2.1/", "93.184.216.34", None, 0),
        ("https://169.254.169.254/", "93.184.216.34", None, 0),
        ("https://[::1]/", "93.184.216.34", None, 0),
        ("https://router.lan/", "93.184.216.34", None, 0),
        ("https://router.home.arpa/", "93.184.216.34", None, 0),
        ("https://cdn.fixture.net:8443/", "93.184.216.34", None, 0),
        ("http://cdn.fixture.net/", "93.184.216.34", None, 0),
        (
            "https://fixture-user@cdn.fixture.net/",
            "93.184.216.34",
            None,
            0,
        ),
        ("https://cdn.fixture.net/", "10.1.2.3", None, 1),
        (
            "https://cdn.fixture.net/",
            "184.216.34.12",
            Some("184.216.34.12"),
            1,
        ),
    ] {
        let start = Instant::now();
        let control = Control::new(1, true);
        let local_ips: Vec<_> = locals.map(str::to_owned).into_iter().collect();
        let mut requests = 0;
        let mut lookups = 0;
        let sample = follow_public(
            "old.test",
            "https://old.test/".parse().unwrap(),
            Chain {
                lease: start..start + Duration::from_secs(1),
                port_count: 10,
                baseline: true,
                address: None,
                local_ips: &local_ips,
            },
            &control,
            |_, _| {
                lookups += 1;
                Ok(lookup_ip.parse().unwrap())
            },
            |_| {
                requests += 1;
                Ok(Some(Output::Redirect(location.to_owned())))
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(requests, 1, "{location}");
        assert_eq!(lookups, expected_lookups, "{location}");
        assert_eq!(sample["verdict"], "error");
        assert_eq!(sample["ok"], false);
        assert!(!sample.to_string().contains("fixture-user"));
    }
}

#[test]
fn legacy_redirect_chain_uses_one_deadline_and_respects_request_and_port_caps() {
    let control = Control::new(1, true);
    let uri: Uri = "https://origin.test/".parse().unwrap();
    for (ports, terminal, calls, good) in
        [(20, 10, 10, true), (20, 11, 10, false), (3, 4, 3, false)]
    {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(1);
        let mut count = 0;
        let result = follow("origin.test", uri.clone(), start, deadline, ports, &control, |hop| {
            count += 1;
            assert_eq!(hop.deadline, deadline);
            Ok(Some(if count == terminal {
                Output::Terminal(json!({"host":"origin.test","code":200,"size":33000,"ok":true,"ttfb_ms":10}))
            } else {
                Output::Redirect("/next".into())
            }))
        }).unwrap().unwrap();
        assert_eq!(count, calls);
        assert_eq!(result["ok"], good);
        if good {
            assert_eq!(result["code"], 200);
        } else {
            assert_eq!(result["code"], 0);
        }
    }
    let now = Instant::now();
    let mut requests = 0;
    let report = follow(
        "origin.test",
        uri,
        now,
        now + Duration::from_millis(30),
        10,
        &control,
        |_| {
            requests += 1;
            thread::sleep(Duration::from_millis(40));
            Ok(Some(Output::Redirect("/unreachable-next".into())))
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(requests, 1);
    assert_eq!(report["code"], 0);
    assert!(report["err"].as_str().unwrap().contains("истекло"));
}

pub(in crate::matrix) fn source_ports(count: u16) -> Vec<u16> {
    assert!(count > 0);
    for _ in 0..64 {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let lo = first.local_addr().unwrap().port();
        if let Some(hi) = lo.checked_add(count - 1) {
            if (1..count)
                .map(|offset| TcpListener::bind((Ipv4Addr::LOCALHOST, lo + offset)))
                .collect::<io::Result<Vec<_>>>()
                .is_ok()
            {
                return (lo..=hi).collect();
            }
        }
    }
    panic!("no {count} adjacent loopback source ports");
}

pub(in crate::matrix) fn fixture_ca(
    dir: &Path,
    hosts: &[&str],
) -> (PathBuf, Arc<rustls::ServerConfig>) {
    let mut authority = rcgen::CertificateParams::default();
    authority.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    authority
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Runs local fixture CA");
    authority.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let authority_key = rcgen::KeyPair::generate().unwrap();
    let root = authority.self_signed(&authority_key).unwrap();
    let issuer = rcgen::Issuer::new(authority, authority_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let mut leaf_params =
        rcgen::CertificateParams::new(hosts.iter().copied().map(str::to_owned).collect::<Vec<_>>())
            .unwrap();
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&key, &issuer).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(
        &ca,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            Base64::encode_string(root.der())
        ),
    )
    .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (ca, Arc::new(config))
}

pub(in crate::matrix) fn fixture_command(
    curl: &Path,
    ca: &Path,
    host: &str,
    destination: u16,
) -> Command {
    let mut cmd = Command::new(curl);
    cmd.arg("--disable")
        .arg("--cacert")
        .arg(ca)
        .arg("--connect-to")
        .arg(format!("{host}:443:127.0.0.1:{destination}"));
    if cfg!(windows) {
        // The private fixture CA has no externally hosted CRL.
        cmd.arg("--ssl-revoke-best-effort");
    }
    cmd
}

#[test]
fn legacy_redirects_follow_verified_local_tls_on_fresh_ports_before_redirect_body() {
    let Ok(curl) = crate::measure::curl() else {
        return;
    };
    let prepared = crate::measure::legacy_matrix_targets(vec!["пример.рф".into()]).unwrap();
    let original = &prepared[0];
    let dir = tempfile::tempdir().unwrap();
    let (ca, config) = fixture_ca(dir.path(), &[&original.authority, "cdn.fixture.net"]);
    let diagnostic = dir.path().join("curl-error.txt");
    let listen = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination = listen.local_addr().unwrap().port();
    listen.set_nonblocking(true).unwrap();
    let chosen = source_ports(3);
    let expected = chosen.clone();
    let sequence = AtomicU32::new(0);
    let control = Control::new(1, true);
    thread::scope(|scope| {
        let queue = &sequence;
        let fixture = scope.spawn(move || {
            let accept_deadline = Instant::now() + Duration::from_secs(8);
            for (index, requested) in ["/dir/nested/start", "/dir/end?raw=%2F", "/final?[fixture]=1"].into_iter().enumerate() {
                let (stream, peer) = loop {
                    match listen.accept() {
                        Ok(accepted) => break accepted,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < accept_deadline, "no TLS redirect request {index}");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(err) => panic!("local TLS listener: {err}"),
                    }
                };
                assert_eq!(peer.port(), expected[index]);
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
                let mut conn = rustls::StreamOwned::new(rustls::ServerConnection::new(config.clone()).unwrap(), stream);
                let mut input = BufReader::new(&mut conn);
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                assert_eq!(line, format!("GET {requested} HTTP/1.1\r\n"));
                let expected_host = if index == 2 { "cdn.fixture.net" } else { &original.authority };
                let mut saw_host = false;
                loop {
                    line.clear();
                    assert!(input.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" { break; }
                    let (header, value) = line.split_once(':').unwrap();
                    if header.eq_ignore_ascii_case("host") {
                        assert_eq!(value.trim(), expected_host);
                        saw_host = true;
                    }
                    for credential in ["authorization", "proxy-authorization", "cookie", "referer"] {
                        assert!(!header.eq_ignore_ascii_case(credential));
                    }
                }
                assert!(saw_host);
                queue.fetch_add(1, Ordering::Release);
                match index {
                    0 => conn.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </information>; rel=preload\r\n\r\nHTTP/1.1 302 Found\r\nLocation: ../end?raw=%2F#ignored\r\nContent-Length: 8192\r\n\r\n").unwrap(),
                    1 => conn.write_all(b"HTTP/1.1 308 Permanent Redirect\r\nLocation: //cdn.fixture.net:443/final?[fixture]=1\r\nContent-Length: 8192\r\n\r\n").unwrap(),
                    _ => {
                        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n").unwrap();
                        for _ in 0..16 { conn.write_all(&[b'x'; 4096]).unwrap(); }
                        conn.conn.send_close_notify();
                    }
                }
                conn.flush().unwrap();
                if index < 2 {
                    // Hold every redirect body back; following must release
                    // the owned connection before another request is made.
                    let read = conn.read(&mut [0]);
                    assert!(matches!(read, Ok(0)) || read.is_err_and(|error| matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)));
                }
            }
        });
        let started = Instant::now();
        let mut ports = chosen.into_iter();
        let public: Ipv4Addr = "93.184.216.34".parse().unwrap();
        let mut resolutions = Vec::new();
        let result = follow_public(
            &original.label,
            format!("https://{}/dir/nested/start", original.authority)
                .parse()
                .unwrap(),
            Chain {
                lease: started..started + Duration::from_secs(7),
                port_count: 3,
                baseline: false,
                address: Some(Ipv4Addr::LOCALHOST),
                local_ips: &[],
            },
            &control,
            |host, deadline| {
                assert_eq!(deadline, started + Duration::from_secs(7));
                resolutions.push(host.to_owned());
                Ok(public)
            },
            |hop| {
                let port = ports.next().unwrap();
                let before = sequence.load(Ordering::Acquire);
                let host = hop.uri.host().unwrap();
                assert_eq!(
                    hop.address,
                    Some(if host == "cdn.fixture.net" {
                        public
                    } else {
                        Ipv4Addr::LOCALHOST
                    })
                );
                let mut cmd = fixture_command(&curl, &ca, host, destination);
                cmd.arg("--show-error").arg("--stderr").arg(&diagnostic);
                let run = probe_hop(
                    cmd,
                    &original.label,
                    (port, port),
                    &control,
                    ProbeLane::Candidate(None),
                    Some(hop),
                )?;
                Ok(run.map(|output| {
                    attest(
                        output,
                        &original.label,
                        before,
                        Ok(sequence.load(Ordering::Acquire)),
                    )
                }))
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(result["host"], original.label);
        assert_eq!(
            result["ok"],
            true,
            "{result}. Fixture curl: {}",
            std::fs::read_to_string(&diagnostic).unwrap_or_default()
        );
        assert_eq!(result["code"], 200);
        assert_eq!(result["size"], 65536);
        assert_eq!(resolutions, ["cdn.fixture.net"]);
        assert_eq!(sequence.load(Ordering::Acquire), 3);
        fixture.join().unwrap();
    });
}
