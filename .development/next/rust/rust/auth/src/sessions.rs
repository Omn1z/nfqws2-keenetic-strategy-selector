use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct State {
    tokens: HashMap<String, Instant>,
    next_sweep: Instant,
}

pub struct Sessions {
    state: Mutex<State>,
    ttl: Duration,
}

impl Sessions {
    pub fn new(ttl: Duration) -> Self {
        Self {
            state: Mutex::new(State {
                tokens: HashMap::new(),
                next_sweep: Instant::now(),
            }),
            ttl,
        }
    }

    pub fn issue(&self) -> io::Result<String> {
        let mut bytes = [0u8; 24];
        getrandom::getrandom(&mut bytes).map_err(|err| io::Error::other(err.to_string()))?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut token = String::with_capacity(48);
        for byte in bytes {
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 15) as usize] as char);
        }
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        // Sweep during issuance instead of running a permanent cleanup thread.
        if now >= state.next_sweep {
            state.tokens.retain(|_, expires| *expires > now);
            state.next_sweep = now + Duration::from_secs(300);
        }
        state.tokens.insert(token.clone(), now + self.ttl);
        Ok(token)
    }

    pub fn valid(&self, token: &str) -> bool {
        if token.len() != 48 {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        match state.tokens.get(token) {
            Some(expires) if *expires > Instant::now() => true,
            Some(_) => {
                state.tokens.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn remove(&self, token: &str) {
        self.state.lock().unwrap().tokens.remove(token);
    }

    pub fn clear(&self) {
        self.state.lock().unwrap().tokens.clear();
    }
}
