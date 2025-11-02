use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
    thread_rng,
};
use std::time::Duration;

pub fn random_name(prefix: String) -> String {
    let mut rng = thread_rng();

    format!("{}_{}", prefix, rng.gen::<u32>())
}

pub fn random_string(length: usize) -> String {
    let mut rng = thread_rng();

    Alphanumeric.sample_string(&mut rng, length)
}

pub fn random_sleeptime(sleep: u64, jitter: u64) -> Duration {
    let mut rng = thread_rng();

    let random_sleeptime = rng.gen_range(jitter..=(2 * jitter));

    Duration::from_secs(sleep + random_sleeptime)
}