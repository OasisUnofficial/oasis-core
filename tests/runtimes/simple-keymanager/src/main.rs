use oasis_core_keymanager::runtime::init::new_keymanager;
use oasis_core_runtime::{common::version::Version, config::Config, types::Features};

mod api;

pub fn main_with_version(version: Version) {
    let init = new_keymanager(api::trusted_policy_signers());
    oasis_core_runtime::start_runtime(
        init,
        Config {
            version,
            features: Some(Features {
                key_manager_master_secret_rotation: true,
                ..Default::default()
            }),
            ..Default::default()
        },
    );
}

#[allow(dead_code)]
pub fn main() {
    main_with_version(Version {
        major: 0,
        minor: 0,
        patch: 0,
    })
}
