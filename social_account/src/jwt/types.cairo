use core::poseidon::poseidon_hash_span;

/// The only issuers the accounts trust. Serialized as the variant index: Google = 0, Apple = 1.
#[derive(Copy, Drop, Serde, PartialEq, Debug)]
pub enum Issuer {
    Google,
    Apple,
}

#[generate_trait]
pub impl IssuerImpl of IssuerTrait {
    /// The `iss` claim this issuer puts in its tokens.
    fn iss(self: Issuer) -> ByteArray {
        match self {
            Issuer::Google => "https://accounts.google.com",
            Issuer::Apple => "https://appleid.apple.com",
        }
    }
}

/// The six claims as they appear in the payload, see `parsing::extract_claims`.
#[derive(Drop)]
pub struct JwtPayload {
    pub iss: ByteArray,
    pub aud: ByteArray,
    pub sub: ByteArray,
    pub nonce: felt252,
    pub exp: u64,
    pub iat: u64,
}

#[generate_trait]
pub impl JwtPayloadImpl of JwtPayloadTrait {
    /// poseidon(iss, aud, sub, pepper)
    /// The SDK computes the same value when it deploys the account. The pepper is a secret the
    /// caller supplies and the contract never checks: it only has to reproduce the stored identity.
    fn identity(self: @JwtPayload, pepper: felt252) -> felt252 {
        self.identity_from_other_aud(self.aud, pepper)
    }

    /// poseidon(iss, other_aud, sub, pepper)
    fn identity_from_other_aud(
        self: @JwtPayload, other_aud: @ByteArray, pepper: felt252,
    ) -> felt252 {
        let mut data: Array<felt252> = array![];
        self.iss.serialize(ref data);
        other_aud.serialize(ref data);
        self.sub.serialize(ref data);
        data.append(pepper);
        poseidon_hash_span(data.span())
    }
}

/// The nonce claim is the SDK's felt as a lowercase `0x` hex string; Google echoes it verbatim.
pub fn parse_hex_felt(s: @ByteArray) -> felt252 {
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

pub fn slot(value: @ByteArray) -> felt252 {
    let mut data: Array<felt252> = array![];
    value.serialize(ref data);
    poseidon_hash_span(data.span())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned so backend/src/social-account.test.ts and the SDK can check their derivation.
    #[test]
    fn identity_reference() {
        let payload = JwtPayload {
            iss: "https://accounts.google.com",
            aud: "123-abc.apps.googleusercontent.com",
            sub: "123456789012345678901",
            nonce: 0,
            exp: 0,
            iat: 0,
        };
        println!("identity(pepper = 0) = {}", payload.identity(0));
        assert!(payload.identity(0) != payload.identity(1));
    }

    #[test]
    fn parses_nonce_hex() {
        assert!(parse_hex_felt(@"0x0") == 0);
        assert!(parse_hex_felt(@"0xff") == 255);
    }
}
