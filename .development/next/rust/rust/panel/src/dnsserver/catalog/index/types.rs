//! Dense bits for the RR names accepted by the Go filter's miekg/dns table.
//! Bit 127 represents wire types without a recognized modifier name.
#[rustfmt::skip]
const TYPES: &[(u16, &str)] = &[
    (1, "A"), (2, "NS"), (3, "MD"), (4, "MF"), (5, "CNAME"), (6, "SOA"),
    (7, "MB"), (8, "MG"), (9, "MR"), (10, "NULL"), (12, "PTR"), (13, "HINFO"),
    (14, "MINFO"), (15, "MX"), (16, "TXT"), (17, "RP"), (18, "AFSDB"), (19, "X25"),
    (20, "ISDN"), (21, "RT"), (23, "NSAP-PTR"), (24, "SIG"), (25, "KEY"),
    (26, "PX"), (27, "GPOS"), (28, "AAAA"), (29, "LOC"), (30, "NXT"), (31, "EID"),
    (32, "NIMLOC"), (33, "SRV"), (34, "ATMA"), (35, "NAPTR"), (36, "KX"),
    (37, "CERT"), (39, "DNAME"), (41, "OPT"), (42, "APL"), (43, "DS"), (44, "SSHFP"),
    (45, "IPSECKEY"), (46, "RRSIG"), (47, "NSEC"), (48, "DNSKEY"), (49, "DHCID"),
    (50, "NSEC3"), (51, "NSEC3PARAM"), (52, "TLSA"), (53, "SMIMEA"), (55, "HIP"),
    (56, "NINFO"), (57, "RKEY"), (58, "TALINK"), (59, "CDS"), (60, "CDNSKEY"),
    (61, "OPENPGPKEY"), (62, "CSYNC"), (63, "ZONEMD"), (64, "SVCB"), (65, "HTTPS"),
    (99, "SPF"), (100, "UINFO"), (101, "UID"), (102, "GID"), (103, "UNSPEC"),
    (104, "NID"), (105, "L32"), (106, "L64"), (107, "LP"), (108, "EUI48"),
    (109, "EUI64"), (128, "NXNAME"), (249, "TKEY"), (250, "TSIG"), (251, "IXFR"),
    (252, "AXFR"), (253, "MAILB"), (254, "MAILA"), (255, "ANY"), (256, "URI"),
    (257, "CAA"), (258, "AVC"), (260, "AMTRELAY"), (261, "RESINFO"), (32768, "TA"),
    (32769, "DLV"),
];
const _: () = assert!(TYPES.len() < 128);

pub(super) fn query_bit(kind: u16) -> u128 {
    1u128
        << TYPES
            .binary_search_by_key(&kind, |(code, _)| *code)
            .unwrap_or(127)
}

pub(super) fn parse(list: &str) -> Option<u128> {
    let mut include = 0;
    let mut exclude = 0;
    for token in list.split('|') {
        let negative = token.strip_prefix('~');
        let name = negative.unwrap_or(token);
        let index = TYPES
            .iter()
            .position(|(_, ty)| name.eq_ignore_ascii_case(ty))?;
        if negative.is_some() {
            exclude |= 1u128 << index;
        } else {
            include |= 1u128 << index;
        }
    }
    Some(if include == 0 {
        !exclude
    } else {
        include & !exclude
    })
}
