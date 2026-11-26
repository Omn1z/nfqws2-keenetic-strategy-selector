//! Portable split-routing documents and atomic edits to the saved router policy.
pub mod discoveries;
mod identity;
pub mod kernel;
pub use identity::Ref;
pub fn public_refs(state: &serde_json::Value) -> Vec<Ref> {
    let mut live = identity::live(state);
    state["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| live.remove(row["id"].as_str()?))
        .collect()
}
mod model;
pub mod observed;
mod policy;
pub mod sources;
mod strict;
#[cfg(test)]
mod tests;
mod transfer;
pub use model::{Routing, Zone};
pub use policy::{copy, insert_top, save, save_settings};
pub use strict::decode;
pub use transfer::{export, import, preview, Document, ImportRequest, Plan};
