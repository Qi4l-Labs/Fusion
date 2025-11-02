use chrono::{Local, Timelike};
use rand::{distributions::{Alphanumeric, DistString}, Rng, SeedableRng};

pub fn random_name(prefix: String) -> String {
    let mut rng = rand::thread_rng();

    format!("{}_{}", prefix, rng.r#gen::<u32>())
}

pub fn random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();

    Alphanumeric.sample_string(&mut rng, length)
}

pub fn generate_time_based_random_number() -> u32 {
    let now = Local::now();
    let hour = now.hour();
    let minute = now.minute();
    let second = now.second();

    let seed = (hour as u64 * 3600 + minute as u64 * 60 + second as u64) as u64;

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let rand_number: u32 = rng.gen_range(1..=1000);

    rand_number
}