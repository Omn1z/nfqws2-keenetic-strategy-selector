use flate2::{write::GzEncoder, Compression};
use std::{
    collections::BTreeMap,
    env, fs, io,
    path::{Path, PathBuf},
};

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=N2S_BUILD_VERSION");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let server = Path::new("../../internal/server");
    let compact = env::var_os("CARGO_FEATURE_COMPACT").is_some();
    let mut assets = String::from("pub static ASSETS: &[(&str, Asset)] = &[\n");
    if compact {
        let root = server
            .join("compactweb")
            .canonicalize()
            .expect("first run npm --prefix frontend run build:compact");
        println!("cargo:rerun-if-changed={}", root.display());
        let modules: BTreeMap<String, String> =
            serde_json::from_reader(fs::File::open(root.join("modules.json"))?)?;
        for (id, url) in modules {
            assert!(url.starts_with(&format!("modules/{id}/")) && url.ends_with(".js"));
            let rel = url.strip_prefix("modules/").unwrap();
            assets.push_str(&format!("({url:?}, Asset::Module({rel:?})),\n"));
        }
        let mut names = vec!["index.html.gz".to_owned()];
        for file in fs::read_dir(root.join("ui"))? {
            names.push(format!("ui/{}", file?.file_name().to_str().unwrap()));
        }
        names.sort();
        for file in names {
            let url = file
                .strip_suffix(".gz")
                .expect("expected precompressed panel asset");
            let path = root.join(file.as_str());
            assets.push_str(&format!(
                "({url:?}, Asset::Embedded(include_bytes!({path:?}))),\n"
            ));
        }
    } else {
        println!("cargo:rerun-if-env-changed=N2S_WEB_INDEX");
        let html = env::var_os("N2S_WEB_INDEX")
            .map(PathBuf::from)
            .unwrap_or_else(|| server.join("web/index.html"));
        println!("cargo:rerun-if-changed={}", html.display());
        let path = out.join("index.html.gz");
        let mut gz = GzEncoder::new(fs::File::create(&path)?, Compression::best());
        io::copy(&mut fs::File::open(html)?, &mut gz)?;
        gz.finish()?;
        assets.push_str(&format!(
            "(\"index.html\", Asset::Embedded(include_bytes!({path:?}))),\n"
        ));
    }
    assets.push_str("];\n");
    fs::write(out.join("assets.rs"), assets)
}
