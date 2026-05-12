pub mod signaling {
    include!(concat!(env!("OUT_DIR"), "/indidus.signaling.rs"));
}

pub mod relay {
    include!(concat!(env!("OUT_DIR"), "/indidus.relay.rs"));
}
