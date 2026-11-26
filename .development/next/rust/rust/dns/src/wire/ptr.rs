use super::{alias, bad, display_name, question, records, terminal, u16_at, u32_at, Section};
use std::io;

/// Read the terminal IN PTR records of an already verified answer. If there
/// is only a CNAME, return the last alias so the caller can query it directly.
pub fn ptr_records(raw: &[u8]) -> io::Result<(Option<String>, Vec<String>)> {
    let question = question(raw)?;
    let flags = u16_at(raw, 2)?;
    if flags & 0xfa00 != 0x8000 || question.class != 1 || question.kind != 12 {
        return Err(bad("dns: expected a complete PTR response"));
    }
    let count =
        u32::from(u16_at(raw, 6)?) + u32::from(u16_at(raw, 8)?) + u32::from(u16_at(raw, 10)?);
    if count > 512 {
        return Err(bad("dns: too many resource records"));
    }
    let mut aliases = Vec::new();
    let mut pointers = Vec::new();
    let mut rcode = flags & 15;
    records(raw, &question, |rr| {
        if rr.kind == 41 {
            rcode |= ((u32_at(raw, rr.ttl_off)? >> 24) as u16) << 4;
        }
        if rr.class == 1 && rr.section == Section::Answer {
            match rr.kind {
                5 => {
                    let next = alias(raw, rr.rdata)?;
                    if aliases
                        .iter()
                        .any(|(from, to)| *from == rr.owner && *to != next)
                    {
                        return Err(bad("dns: conflicting CNAME"));
                    }
                    aliases.push((rr.owner, next));
                }
                12 => pointers.push((rr.owner, alias(raw, rr.rdata)?)),
                _ => (),
            }
        }
        Ok(())
    })?;
    match rcode {
        0 => (),
        3 => return Ok((None, Vec::new())),
        _ => return Err(io::Error::other(format!("dns: response code {rcode}"))),
    }
    let owner =
        terminal(&question.name, &aliases).ok_or_else(|| bad("dns: invalid CNAME chain"))?;
    let final_alias = (owner != question.name).then(|| display_name(owner));
    let names = pointers
        .into_iter()
        .filter(|(from, _)| from == owner)
        .map(|(_, target)| display_name(&target))
        .collect();
    Ok((final_alias, names))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_query;

    fn name(host: &str) -> Vec<u8> {
        let question = build_query(host, 12, 1).unwrap();
        question[12..question.len() - 4].to_vec()
    }

    fn append(answer: &mut Vec<u8>, owner: &[u8], kind: u16, rdata: &[u8]) {
        answer[7] += 1;
        answer.extend_from_slice(owner);
        answer.extend(kind.to_be_bytes());
        answer.extend([0, 1, 0, 0, 0, 30]);
        answer.extend((rdata.len() as u16).to_be_bytes());
        answer.extend_from_slice(rdata);
    }

    #[test]
    fn ptr_response_follows_the_owner_chain_and_rejects_truncation() {
        let mut answer = build_query("80.2.0.192.in-addr.arpa", 12, 1).unwrap();
        answer[2..4].copy_from_slice(&[0x81, 0x80]);
        append(
            &mut answer,
            &name("unrelated.example"),
            12,
            &name("wrong.example"),
        );
        append(&mut answer, &[0xc0, 12], 5, &name("alias.example"));
        assert_eq!(
            ptr_records(&answer).unwrap(),
            (Some("alias.example.".into()), Vec::new())
        );
        append(
            &mut answer,
            &name("alias.example"),
            12,
            &name("Node.Example"),
        );
        assert_eq!(ptr_records(&answer).unwrap().1, ["node.example."]);
        assert!(ptr_records(&answer[..answer.len() - 1]).is_err());
        answer[2] |= 2;
        assert!(ptr_records(&answer).is_err());
    }
}
