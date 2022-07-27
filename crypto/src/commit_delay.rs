use std::num::TryFromIntError;

/// These constants intend to ramp up the delay and flatten the curve for later positions
const DELAY_RAMP_UP_MULTIPLIER: f32 = 120.0;
const DELAY_RAMP_UP_SUB: u64 = 106;

pub(crate) fn calculate_delay(self_index: usize, epoch: u64, total_members: usize) -> Result<u64, TryFromIntError> {
    let self_index: u64 = self_index.try_into()?;
    let total_members: u64 = total_members.try_into()?;
    let position = ((epoch % total_members) + (self_index % total_members)) % total_members + 1;
    let result = match position {
        1 => 0,
        2 => 15,
        3 => 30,
        _ => (((position as f32).ln() * DELAY_RAMP_UP_MULTIPLIER) as u64).saturating_sub(DELAY_RAMP_UP_SUB),
    };
    Ok(result)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_calculate_delay_single() {
        let (self_index, epoch, total_members) = (0, 0, 1);
        let delay = calculate_delay(self_index, epoch, total_members).unwrap();
        assert_eq!(delay, 0);
    }

    #[test]
    pub fn test_calculate_delay_max() {
        let (self_index, epoch, total_members) = (usize::MAX, u64::MAX, usize::MAX);
        let delay = calculate_delay(self_index, epoch, total_members).unwrap();
        assert_eq!(delay, 0);
    }

    #[test]
    pub fn test_calculate_delay_min() {
        let (self_index, epoch, total_members) = (usize::MIN, u64::MIN, usize::MAX);
        let delay = calculate_delay(self_index, epoch, total_members).unwrap();
        assert_eq!(delay, 0);
    }

    #[test]
    #[should_panic]
    pub fn test_calculate_delay_panic() {
        let (self_index, epoch, total_members) = (0, 0, usize::MIN);
        // total members can never be 0 as there's no group with 0 members and it will panic
        // when trying to calculate the remainder of 0
        calculate_delay(self_index, epoch, total_members).unwrap();
    }

    #[test]
    pub fn test_calculate_delay_min_max() {
        let (self_index, epoch, total_members) = (usize::MIN, u64::MAX, usize::MAX);
        let delay = calculate_delay(self_index, epoch, total_members).unwrap();
        assert_eq!(delay, 0);
    }

    #[test]
    pub fn test_calculate_delay_first() {
        let (self_index, epoch, total_members) = (9, 1, 10);
        let delay = calculate_delay(self_index, epoch, total_members).unwrap();
        assert_eq!(delay, 0);
    }

    #[test]
    pub fn test_calculate_delay_second() {
        let (self_index, epoch, total_members) = (0, 1, 10);
        let delay = calculate_delay(self_index, epoch, total_members).unwrap();
        assert_eq!(delay, 15);
    }

    #[test]
    pub fn test_calculate_delay_third() {
        let (self_index, epoch, total_members) = (1, 1, 10);
        let delay = calculate_delay(self_index, epoch, total_members).unwrap();
        assert_eq!(delay, 30);
    }

    #[test]
    pub fn test_calculate_delay_n() {
        let epoch = 1;
        let total_members = 10;

        let indexes_delays = [
            (2, 60),
            (3, 87),
            (4, 109),
            (5, 127),
            (6, 143),
            (7, 157),
            (8, 170),
            // wrong but it shouldn't cause problems
            (10, 15),
        ];

        for (self_index, expected_delay) in indexes_delays {
            let delay = calculate_delay(self_index, epoch, total_members).unwrap();
            assert_eq!(delay, expected_delay);
        }
    }
}
