extern crate sodiumoxide;
use sodiumoxide::crypto::box_;

    pub fn generate_new_keypair() -> (box_::PublicKey, box_::SecretKey){
        return box_::gen_keypair();
    }

    pub fn get_nonce() -> box_::Nonce{
        return box_::gen_nonce();
    }

    pub fn precompute(pk: &box_::PublicKey, sk: &box_::SecretKey) -> box_::PrecomputedKey {
        return box_::precompute(pk, sk);
    }

    pub fn encrypt(data: &[u8], nonce: &box_::Nonce, precomputed: &box_::PrecomputedKey) -> Vec<u8> {
        return box_::seal_precomputed(data, nonce,
                                      precomputed);
    }

    pub fn decrypt(encrypted_data: &Vec<u8>, nonce: &box_::Nonce, precomputed: &box_::PrecomputedKey) -> Vec<u8> {
        return box_::open_precomputed(&encrypted_data, &nonce,
                                      precomputed).unwrap();
    }