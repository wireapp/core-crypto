use super::MlsConversation;

impl MlsConversation {
    /// These constants intend to ramp up the delay and flatten the curve for later positions
    const DELAY_RAMP_UP_MULTIPLIER: f32 = 120.0;
    const DELAY_RAMP_UP_SUB: u64 = 106;

    /// Helps consumer by providing a deterministic delay for him to commit its pending proposal.
    /// It depends on the index of the client in the ratchet tree
    /// * `self_index` - ratchet tree index of self client
    /// * `epoch` - current group epoch
    /// * `nb_members` - number of clients in the group
    pub fn compute_next_commit_delay(&self) -> u64 {
        let epoch = self.group.epoch().as_u64();
        let nb_members = self.group.members().len() as u64;
        let own_index = self.group.own_leaf_index() as u64;
        Self::calculate_delay(own_index, epoch, nb_members)
    }

    fn calculate_delay(self_index: u64, epoch: u64, nb_members: u64) -> u64 {
        let position = ((epoch % nb_members) + (self_index % nb_members)) % nb_members + 1;
        match position {
            1 => 0,
            2 => 15,
            3 => 30,
            _ => (((position as f32).ln() * Self::DELAY_RAMP_UP_MULTIPLIER) as u64)
                .saturating_sub(Self::DELAY_RAMP_UP_SUB),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn calculate_delay_single() {
        let (self_index, epoch, nb_members) = (0, 0, 1);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    pub fn calculate_delay_max() {
        let (self_index, epoch, nb_members) = (u64::MAX, u64::MAX, u64::MAX);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    pub fn calculate_delay_min() {
        let (self_index, epoch, nb_members) = (u64::MIN, u64::MIN, u64::MAX);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    #[should_panic]
    pub fn calculate_delay_panic() {
        let (self_index, epoch, nb_members) = (0, 0, u64::MIN);
        // total members can never be 0 as there's no group with 0 members and it will panic
        // when trying to calculate the remainder of 0
        MlsConversation::calculate_delay(self_index, epoch, nb_members);
    }

    #[test]
    pub fn calculate_delay_min_max() {
        let (self_index, epoch, nb_members) = (u64::MIN, u64::MAX, u64::MAX);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    pub fn calculate_delay_n() {
        let epoch = 1;
        let nb_members = 10;

        let indexes_delays = [
            (0, 15),
            (1, 30),
            (2, 60),
            (3, 87),
            (4, 109),
            (5, 127),
            (6, 143),
            (7, 157),
            (8, 170),
            (9, 0),
            // wrong but it shouldn't cause problems
            (10, 15),
        ];

        for (self_index, expected_delay) in indexes_delays {
            let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
            assert_eq!(delay, expected_delay);
        }
    }
}
