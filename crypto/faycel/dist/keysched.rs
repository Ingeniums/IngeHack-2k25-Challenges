const PBOX: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const P2: [u8; 48] = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51,
    30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
];

const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2];

pub struct KeyExpansion {
    initial: Vec<u8>,
    pub round_keys: Vec<[u8; 8]>,
}

impl KeyExpansion {
    pub fn new(key: &Vec<u8>) -> Self {
        Self {
            initial: key.clone(),
            round_keys: vec![],
        }
    }

    pub fn setup(&mut self) {
        self.set_round_keys();
    }

    fn permute_initial_key(&self) -> [u8; 56] {
        let bits: Vec<u8> = self
            .initial
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
            .collect();

        PBOX.map(|e| bits[e as usize])
    }

    fn permute_round_keys(&self, round_key: &Vec<u8>) -> [u8; 8] {
        let bits = P2.map(|e| round_key[e as usize]);

        let mut result = [0; 8];
        for (i, byte) in bits.iter().enumerate() {
            result[i / 8] |= byte << (i % 8);
        }

        result[6] = result[0];
        result[7] = result[1];

        result
    }

    fn set_round_keys(&mut self) {
        let permuted_key = self.permute_initial_key();
        let mut c0 = permuted_key[..28].to_vec();
        let mut d0 = permuted_key[28..].to_vec();

        for shift in SHIFTS {
            c0.rotate_left(shift as usize);
            d0.rotate_left(shift as usize);
            let round_key =
                self.permute_round_keys(&c0.iter().chain(d0.iter()).copied().collect::<Vec<u8>>());
            self.round_keys.push(round_key);
        }
    }
}
