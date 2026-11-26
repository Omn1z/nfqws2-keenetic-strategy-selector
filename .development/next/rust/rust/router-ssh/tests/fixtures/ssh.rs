// A stub OpenSSH client for CLI tests. Never opens a socket or shell.
use std::{
    env, fs,
    io::{self, Read, Write},
    process::{self, Command},
    thread,
    time::Duration,
};

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let password = env::var("ROUTER_PASS").unwrap();
    assert!(!args.iter().any(|a| a.contains(&password)));
    assert!(args.windows(2).any(|a| a == ["-p", "2345"]));
    assert!(args.windows(2).any(|a| a == ["-l", "fixture-user"]));
    let override_used = args.last().is_some_and(|command| command == "exec ok");
    let expected_host = if override_used {
        "127.0.0.2"
    } else {
        "127.0.0.1"
    };
    assert_eq!(&args[args.len() - 3..args.len() - 1], ["--", expected_host]);
    assert!(
        password
            == if override_used {
                "override-password"
            } else {
                " fixture-password "
            }
    );
    assert_eq!(env::var("SSH_ASKPASS_REQUIRE").unwrap(), "force");
    let answer = Command::new(env::var_os("SSH_ASKPASS").unwrap())
        .arg("fixture-user@fixture-router's password:")
        .output()
        .unwrap();
    assert!(answer.status.success());
    let mut expected = password.into_bytes();
    expected.push(b'\n');
    assert!(
        answer.stdout == expected,
        "password reader did not preserve input"
    );
    let command = args.last().unwrap().as_str();
    let file = env::var_os("N2S_FIXTURE_DATA").unwrap();
    match command {
        "exec ok" => println!("exec output"),
        "sleep" => thread::sleep(Duration::from_secs(10)),
        "exec fail" => process::exit(23),
        "cat 'bad'" => {
            print!("incomplete");
            process::exit(17);
        }
        "cat './-file'" => io::stdout().write_all(&fs::read(file).unwrap()).unwrap(),
        c if c.starts_with("set -e; mkdir -p ") => {
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes).unwrap();
            assert!(c.contains("chmod -- '0755'"));
            assert!(c.contains("'./-d/foo'\"'\"'bar'"));
            assert!(c.contains(&format!(" -eq {} ]", bytes.len())));
            fs::write(file, bytes).unwrap();
        }
        "uname -a; date; uptime" => process::exit(11),
        c if c.starts_with("ip rule show;") => println!("route fixture"),
        _ => process::exit(99),
    }
}
