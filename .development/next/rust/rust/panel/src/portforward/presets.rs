use super::{PortRange, Preset, Profile};

const SOURCE_0: &str = "Activision Support: Ports Used for Call of Duty Games, updated 2026-02-03";
const SOURCE_1: &str = "PortForward: Delta Force PC";

const PROFILES_COD_BO7: &[Profile] = &[
    Profile {
        id: "steam",
        name: "Steam",
        tcp: &[
            PortRange::new(3074, 3074),
            PortRange::new(27015, 27015),
            PortRange::new(27036, 27036),
        ],
        udp: &[
            PortRange::new(3074, 3074),
            PortRange::new(27015, 27015),
            PortRange::new(27031, 27036),
        ],
    },
    Profile {
        id: "pc",
        name: "PC",
        tcp: &[
            PortRange::new(3074, 3074),
            PortRange::new(4000, 4000),
            PortRange::new(6112, 6119),
            PortRange::new(20500, 20500),
            PortRange::new(20510, 20510),
            PortRange::new(27014, 27050),
            PortRange::new(28960, 28960),
        ],
        udp: &[
            PortRange::new(3074, 3074),
            PortRange::new(3478, 3478),
            PortRange::new(4379, 4380),
            PortRange::new(6112, 6119),
            PortRange::new(20500, 20500),
            PortRange::new(20510, 20510),
            PortRange::new(27000, 27031),
            PortRange::new(27036, 27036),
            PortRange::new(28960, 28960),
        ],
    },
    Profile {
        id: "playstation",
        name: "PlayStation",
        tcp: &[PortRange::new(3478, 3480)],
        udp: &[PortRange::new(3074, 3074), PortRange::new(3478, 3479)],
    },
    Profile {
        id: "xbox",
        name: "Xbox",
        tcp: &[PortRange::new(3074, 3074)],
        udp: &[
            PortRange::new(88, 88),
            PortRange::new(500, 500),
            PortRange::new(3074, 3074),
            PortRange::new(3544, 3544),
            PortRange::new(4500, 4500),
        ],
    },
];

const PROFILES_COD_MW_2019: &[Profile] = &[
    Profile {
        id: "pc",
        name: "PC",
        tcp: &[PortRange::new(3074, 3074), PortRange::new(27014, 27050)],
        udp: &[
            PortRange::new(3074, 3074),
            PortRange::new(3478, 3478),
            PortRange::new(4379, 4380),
            PortRange::new(27000, 27031),
            PortRange::new(27036, 27036),
        ],
    },
    Profile {
        id: "playstation",
        name: "PlayStation",
        tcp: &[PortRange::new(1935, 1935), PortRange::new(3478, 3480)],
        udp: &[PortRange::new(3074, 3074), PortRange::new(3478, 3479)],
    },
    Profile {
        id: "xbox",
        name: "Xbox",
        tcp: &[PortRange::new(3074, 3074)],
        udp: &[
            PortRange::new(88, 88),
            PortRange::new(500, 500),
            PortRange::new(3074, 3074),
            PortRange::new(3075, 3075),
            PortRange::new(3544, 3544),
            PortRange::new(4500, 4500),
        ],
    },
];

const PROFILES_COD_VANGUARD: &[Profile] = &[
    Profile {
        id: "pc",
        name: "PC",
        tcp: &[PortRange::new(3074, 3074), PortRange::new(27014, 27050)],
        udp: &[PortRange::new(3074, 3079)],
    },
    Profile {
        id: "playstation",
        name: "PlayStation",
        tcp: &[PortRange::new(1935, 1935), PortRange::new(3478, 3480)],
        udp: &[PortRange::new(3074, 3079), PortRange::new(3478, 3479)],
    },
    Profile {
        id: "xbox",
        name: "Xbox",
        tcp: &[PortRange::new(3074, 3074)],
        udp: &[
            PortRange::new(88, 88),
            PortRange::new(500, 500),
            PortRange::new(3074, 3079),
            PortRange::new(3544, 3544),
            PortRange::new(4500, 4500),
        ],
    },
];

const PROFILES_DELTA_FORCE: &[Profile] = &[Profile {
    id: "pc",
    name: "PC",
    tcp: &[],
    udp: &[PortRange::new(3568, 3569)],
}];

pub(super) const PRESETS: &[Preset] = &[
    Preset {
        id: "cod-bo7",
        name: "Call Of Duty Black Ops 7",
        source: SOURCE_0,
        profiles: PROFILES_COD_BO7,
    },
    Preset {
        id: "cod-bo6",
        name: "Call Of Duty Black Ops 6",
        source: SOURCE_0,
        profiles: PROFILES_COD_BO7,
    },
    Preset {
        id: "cod-mw-2023",
        name: "Call Of Duty Modern Warfare 2023",
        source: SOURCE_0,
        profiles: PROFILES_COD_BO7,
    },
    Preset {
        id: "cod-mw-2022",
        name: "Call Of Duty Modern Warfare 2022",
        source: SOURCE_0,
        profiles: PROFILES_COD_BO7,
    },
    Preset {
        id: "cod-mw-2019",
        name: "Call Of Duty Modern Warfare 2019",
        source: SOURCE_0,
        profiles: PROFILES_COD_MW_2019,
    },
    Preset {
        id: "cod-vanguard",
        name: "Call Of Duty Vanguard",
        source: SOURCE_0,
        profiles: PROFILES_COD_VANGUARD,
    },
    Preset {
        id: "delta-force",
        name: "Delta Force",
        source: SOURCE_1,
        profiles: PROFILES_DELTA_FORCE,
    },
];
