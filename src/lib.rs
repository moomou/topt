extern crate crypto;

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;
use data_encoding::BASE32;
use qrcode::render::unicode;
use qrcode::QrCode;
use std::convert::TryInto;
use std::mem::transmute;

const F: u64 = 30;
const DIGITS: u32 = 6;

pub fn topt(epoch_sec: u64, key: &[u8]) -> String {
    // round time_val to nearest 30 sec
    let t = i2b_time(epoch_sec / F);
    let hmac_hash = lib_hmac(key, &t[..]);
    let trc_hash = dynamic_truncate(&hmac_hash);
    format!("{:06}", trc_hash % ((10 as u32).pow(DIGITS)))
}

fn dynamic_truncate(hash: &Vec<u8>) -> u32 {
    let offset = hash
        .last()
        .map(|v| (v & 0xF) as usize)
        .expect("invalid hash received");

    let slice = u32::from_be_bytes(hash[offset..offset + 4].try_into().expect("invalid slice"));

    // take 32 bit from this number with a leading zero
    slice & 0x7FFFFFFF
}

// returns 160bit HMAC-SHA1 hash
fn lib_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::new(Sha1::new(), key);
    mac.input(message);
    mac.result().code().to_vec()
}

fn i2b_time(time: u64) -> [u8; 8] {
    unsafe { transmute(time.to_be()) }
}

pub fn google_auth_compat(secret: &[u8]) -> String {
    BASE32.encode(secret).replace("=", "")
}

pub fn show_qr_code(secret: &[u8]) {
    let google_auth_qr_code = format!(
        "otpauth://totp/Short:moomou@localhost?secret={}&issuer=Short",
        google_auth_compat(secret)
    );

    let code = QrCode::new(google_auth_qr_code).unwrap();
    let image = code.render::<unicode::Dense1x2>().build();

    println!("{}", image);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_dynamic_truncate() {
        // see https://jacob.jkrall.net/totp
        let hash = vec![
            0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19,
            0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a,
        ];
        let truncated = dynamic_truncate(&hash);
        assert_eq!(truncated, 0x50ef7f19);
        assert_eq!(
            format!("{:06}", truncated % ((10 as u32).pow(DIGITS)),),
            "872921"
        );
    }

    #[test]
    #[ignore]
    fn topt_works() {
        let epoch_sec = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => panic!("failed to fetch time"),
        };

        let secret = b"M1234";
        // on Google auth app, enter 'JUYTEMZU' which is base32 of `secret`
        assert_eq!(topt(epoch_sec, secret), "meh");
    }
}
