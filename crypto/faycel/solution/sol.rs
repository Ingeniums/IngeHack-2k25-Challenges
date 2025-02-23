// https://en.wikipedia.org/wiki/Feistel_cipher
fn decrypt(ct: &Vec<u8>, keys: &Vec<[u8; 8]>) -> Vec<u8> {
    let mut out = Vec::new();

    for i in (0..ct.len()).step_by(16) {
        let mut r = ct[i..i + 8].to_vec();
        let mut l = ct[i + 8..i + 16].to_vec();

        for key in keys.iter().rev() {
            (l, r) = (xor(&r, &round(&l, &key)), l);
        }

        out.extend(&l);
        out.extend(&r);
    }

    out
}
