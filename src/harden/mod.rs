pub mod checks;

use crate::types::HardenFinding;

pub fn run() -> Vec<HardenFinding> {
    checks::run_all()
}
