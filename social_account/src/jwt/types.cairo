use core::poseidon::poseidon_hash_span;

/// The five claims as they appear in the payload, see `parsing::extract_claims`.
#[derive(Drop)]
pub struct JwtPayload {
    pub iss: ByteArray,
    pub aud: ByteArray,
    pub sub: ByteArray,
    pub nonce: ByteArray,
    pub exp: u64,
}

/// The claims recovered from the jwt payload
#[derive(Drop, Copy)]
pub struct JwtClaims {
    /// poseidon(iss, aud, sub): the Google identity bound to the account.
    pub identity: felt252,
    /// The `nonce` claim.
    pub nonce: felt252,
    /// The `exp` claim, unix seconds.
    pub exp: u64,
}

pub impl JwtPayloadToJwtClaims of TryInto<JwtPayload, JwtClaims> {
    fn try_into(self: JwtPayload) -> Option<JwtClaims> {
        Some(
            JwtClaims {
                identity: identity(@self.iss, @self.aud, @self.sub),
                nonce: parse_hex_felt(@self.nonce),
                exp: self.exp,
            },
        )
    }
}

/// poseidon over the three claims as serialized ByteArrays. The SDK computes the same value
/// when it deploys the account.
pub fn identity(iss: @ByteArray, aud: @ByteArray, sub: @ByteArray) -> felt252 {
    let mut data: Array<felt252> = array![];
    iss.serialize(ref data);
    aud.serialize(ref data);
    sub.serialize(ref data);
    poseidon_hash_span(data.span())
}

/// The nonce claim is the SDK's felt as a lowercase `0x` hex string; Google echoes it verbatim.
fn parse_hex_felt(s: @ByteArray) -> felt252 {
    assert(s.len() > 2 && s.at(0).unwrap() == '0' && s.at(1).unwrap() == 'x', 'BAD_NONCE');
    let mut value: u256 = 0;
    let mut i = 2;
    while i < s.len() {
        let c = s.at(i).unwrap();
        let digit: u8 = if c >= '0' && c <= '9' {
            c - '0'
        } else {
            assert(c >= 'a' && c <= 'f', 'BAD_NONCE');
            c - 'a' + 10
        };
        value = value * 16 + digit.into();
        i += 1;
    }
    value.try_into().expect('BAD_NONCE')
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn parses_nonce_hex() {
        assert!(parse_hex_felt(@"0x0") == 0);
        assert!(parse_hex_felt(@"0xff") == 255);
    }
}
