//! RS256 check of a Google ID token, plus the claims `recover` needs.
//!
//! Runs inside the prover as a virtual call. The signature is verified by `jwt::rsa` (garaga's
//! check without circuits) against the JwkRegistry key the caller names by `kid`. The reduction
//! witnesses it needs cannot be derived from the token, so the client sends them as `rsa_hint`.

use alexandria_encoding::base64::Base64ByteArrayDecoder;
use garaga::signatures::rsa::RSA2048SignatureWithHint;
use starknet::ContractAddress;
use crate::jwt::rec_aud_component::{
    IWhitelistedAudienceRecoverableDispatcher, IWhitelistedAudienceRecoverableDispatcherTrait,
};
use super::parsing::extract_payload;
use super::registry::{IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait};
use super::rsa::is_valid_rsa2048_sha256_signature;
use super::types::JwtPayload;

/// Verifies a token given as its two base64url segments and returns its claims.
///
/// The caller splits the token at the dots. The third segment is not needed because `rsa_hint`
/// already carries the signature. Splitting off chain is safe since the signature is checked over
/// `header.payload` rebuilt here, and the claims are read from those same segments, so only the
/// genuine split verifies.
///
/// The header is never decoded. `kid` in combination with payload's `iss` selects which registry
/// key to try.
/// A wrong `iss`, `kid` pair just fails the signature check. The `alg` claim is ignored
/// for the same reason: RS256 is the only algorithm ever run, so nothing dispatches on it.
///
/// `rsa_hint` is what `rsa2048Sha256CalldataBuilder` produced for this token.
pub fn verify_and_extract(
    header_b64: ByteArray,
    payload_b64: ByteArray,
    kid: ByteArray,
    rsa_hint: Span<felt252>,
    jwk_registry: ContractAddress,
) -> JwtPayload {
    let signing_input = header_b64 + "." + payload_b64.clone();
    let payload = extract_payload(base64url_decode(@payload_b64));
    let key = IJwkRegistryDispatcher { contract_address: jwk_registry }
        .get_key(payload.iss.clone(), kid);

    let mut hint = rsa_hint;
    let sig = Serde::<RSA2048SignatureWithHint>::deserialize(ref hint).expect('BAD_RSA_HINT');
    assert(is_valid_rsa2048_sha256_signature(@sig, @key, @signing_input), 'BAD_SIGNATURE');

    payload
}

pub fn verify_recovery_aud(jwt_payload: @JwtPayload, jwk_registry: ContractAddress) -> bool {
    IWhitelistedAudienceRecoverableDispatcher { contract_address: jwk_registry }
        .is_whitelisted(jwt_payload.iss.clone(), jwt_payload.aud.clone())
}

fn base64url_decode(part: @ByteArray) -> ByteArray {
    assert(part.len() % 4 != 1, 'B64_BAD_LENGTH');
    let mut padded = part.clone();
    while padded.len() % 4 != 0 {
        padded.append_byte('=');
    }
    Base64ByteArrayDecoder::decode(padded)
}

#[cfg(test)]
mod tests {
    use core::poseidon::poseidon_hash_span;
    use garaga::signatures::rsa::RSA2048PublicKey;
    use snforge_std::fs::{FileTrait, read_txt};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address};
    use starknet::{ContractAddress, SyscallResultTrait};
    use super::verify_and_extract;
    use super::super::registry::{IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait};
    use super::super::types::Issuer;

    /// The self-signed token in tests/data/test_jwt.txt, made by
    /// backend/src/scripts/gen-jwt-fixture.ts: header, payload, the key's 24 limbs, then the
    /// garaga hint for this exact token. The constants below mirror the script.
    #[derive(Drop)]
    struct Token {
        header: ByteArray,
        payload: ByteArray,
        key: RSA2048PublicKey,
        hint: Span<felt252>,
    }

    fn token() -> Token {
        let mut felts = read_txt(@FileTrait::new("tests/data/test_jwt.txt")).span();
        let header = Serde::<ByteArray>::deserialize(ref felts).unwrap();
        let payload = Serde::<ByteArray>::deserialize(ref felts).unwrap();
        let key = Serde::<RSA2048PublicKey>::deserialize(ref felts).unwrap();
        Token { header, payload, key, hint: felts }
    }

    fn kid() -> ByteArray {
        "test-kid"
    }

    /// The payload with the lowest bit of its last base64url digit flipped. The fixture's
    /// length makes that bit padding, so the decoded bytes are unchanged and only the signing
    /// input differs.
    fn tampered_payload() -> ByteArray {
        let payload = token().payload;
        let last = payload.len() - 1;
        let mut out: ByteArray = "";
        let mut i = 0;
        while i < last {
            out.append_byte(payload.at(i).unwrap());
            i += 1;
        }
        let c = payload.at(last).unwrap();
        // Each run of the alphabet starts at an even value (A=0, a=26, 0=52, -=62), so the
        // low bit flips within the run.
        let flipped = if c == '-' {
            '_'
        } else if c == '_' {
            '-'
        } else {
            let base = if c >= 'a' {
                'a'
            } else if c >= 'A' {
                'A'
            } else {
                '0'
            };
            base + ((c - base) ^ 1)
        };
        out.append_byte(flipped);
        out
    }

    /// A registry holding the test key under Google's iss.
    fn registry_with_test_key() -> ContractAddress {
        let owner: ContractAddress = 'owner'.try_into().unwrap();
        let class = declare("JwkRegistry").unwrap_syscall().contract_class();
        let (registry_address, _) = class.deploy(@array![owner.into()]).unwrap_syscall();
        start_cheat_caller_address(registry_address, owner);
        IJwkRegistryDispatcher { contract_address: registry_address }
            .set_key(Issuer::Google, kid(), token().key);
        registry_address
    }

    #[test]
    fn verifies_the_test_token() {
        let t = token();
        let claims = verify_and_extract(
            t.header, t.payload, kid(), t.hint, registry_with_test_key(),
        );
        assert!(claims.exp == 2_000_000);
        assert!(claims.iat == 1_000_000);
        assert!(claims.nonce == poseidon_hash_span([0x222, 0x333].span()));
        assert!(claims.iss == "https://accounts.google.com");
        assert!(claims.aud == "aud");
        assert!(claims.sub == "sub-1");
    }

    #[test]
    #[should_panic(expected: 'BAD_SIGNATURE')]
    fn rejects_tampered_payload() {
        let t = token();
        verify_and_extract(t.header, tampered_payload(), kid(), t.hint, registry_with_test_key());
    }

    /// A hint whose fourth reduction witness is off by one in one limb. Only the exact integer
    /// check of that reduction can catch it.
    #[test]
    #[should_panic(expected: 'BAD_SIGNATURE')]
    fn rejects_tampered_reduction_witness() {
        let t = token();
        let mut hint: Array<felt252> = array![];
        let mut i = 0;
        for f in t.hint {
            hint.append(if i == 48 + 48 * 3 + 5 {
                *f + 1
            } else {
                *f
            });
            i += 1;
        }
        verify_and_extract(t.header, t.payload, kid(), hint.span(), registry_with_test_key());
    }

    #[test]
    #[should_panic(expected: 'UNKNOWN_KID')]
    fn rejects_unknown_kid() {
        let owner: ContractAddress = 'owner'.try_into().unwrap();
        let class = declare("JwkRegistry").unwrap().contract_class();
        let (empty_registry, _) = class.deploy(@array![owner.into()]).unwrap();
        let t = token();
        verify_and_extract(t.header, t.payload, kid(), t.hint, empty_registry);
    }
}
