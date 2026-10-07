//! RS256 check of a Google ID token, plus the claims `recover` needs.
//!
//! Runs inside the prover as a virtual call. The signature is verified with garaga against the
//! JwkRegistry key the caller names by `kid`. The reduction witnesses garaga needs cannot be
//! derived from the token, so the client sends them as `rsa_hint`.

use alexandria_encoding::base64::Base64ByteArrayDecoder;
use garaga::signatures::rsa::{RSA2048SignatureWithHint, is_valid_rsa2048_sha256_signature};
use starknet::ContractAddress;
use super::parsing::extract_claims;
use super::registry::{IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait};
use super::types::{JwtClaims, JwtPayloadToJwtClaims};

/// Verifies a token given as its two base64url segments and returns its claims.
///
/// The caller splits the token at the dots; the third segment is not needed because `rsa_hint`
/// already carries the signature. Splitting off chain is safe: the signature is checked over
/// `header.payload` rebuilt here, and the claims are read from those same segments, so only the
/// genuine split verifies.
///
/// The header is never decoded. `kid` only selects which registry key to try, and every registry
/// key is Google's, so a wrong `kid` just fails the signature check. The `alg` claim is ignored
/// for the same reason: RS256 is the only algorithm ever run, so nothing dispatches on it.
///
/// `rsa_hint` is what `rsa2048Sha256CalldataBuilder` produced for this token: signature,
/// expected message and 17 reduction witnesses. Only its first 864 felts are read.
pub fn verify_and_extract(
    header_b64: ByteArray,
    payload_b64: ByteArray,
    kid: ByteArray,
    rsa_hint: Span<felt252>,
    jwk_registry: ContractAddress,
) -> JwtClaims {
    let signing_input = header_b64 + "." + payload_b64.clone();
    let key = IJwkRegistryDispatcher { contract_address: jwk_registry }.get_key(kid);

    let mut hint = rsa_hint;
    let sig = Serde::<RSA2048SignatureWithHint>::deserialize(ref hint).expect('BAD_RSA_HINT');
    assert(is_valid_rsa2048_sha256_signature(@sig, @key, @signing_input), 'BAD_SIGNATURE');

    extract_claims(base64url_decode(@payload_b64)).try_into().expect('BAD_PAYLOAD')
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
    use garaga::signatures::rsa::RSA2048PublicKey;
    use snforge_std::fs::{FileTrait, read_txt};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address};
    use starknet::{ContractAddress, SyscallResultTrait};
    use crate::jwt::types::identity;
    use super::verify_and_extract;
    use super::super::registry::{IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait};

    // A real Google ID token. Its key is still in Google's JWKS; the fixtures under tests/data
    // hold that key and the garaga hint for this exact token.
    fn kid() -> ByteArray {
        "REDACTED_KID"
    }

    fn header() -> ByteArray {
        "REDACTED_JWT_HEADER"
    }

    /// Everything but the last character, so a test can swap it.
    fn payload_head() -> ByteArray {
        "REDACTED_JWT_PAYLOAD"
    }

    fn payload() -> ByteArray {
        payload_head() + "0"
    }

    fn rsa_hint() -> Span<felt252> {
        read_txt(@FileTrait::new("tests/data/google_jwt_rsa_hint.txt")).span()
    }

    /// A registry holding Google's key for the token's kid.
    fn registry_with_google_key() -> ContractAddress {
        let owner: ContractAddress = 'owner'.try_into().unwrap();
        let class = declare("JwkRegistry").unwrap_syscall().contract_class();
        let (registry_address, _) = class.deploy(@array![owner.into()]).unwrap_syscall();
        let mut felts = read_txt(@FileTrait::new("tests/data/google_jwk_pub_key.txt")).span();
        let key = Serde::<RSA2048PublicKey>::deserialize(ref felts).unwrap();
        start_cheat_caller_address(registry_address, owner);
        IJwkRegistryDispatcher { contract_address: registry_address }.set_key(kid(), key);
        registry_address
    }

    #[test]
    fn verifies_real_google_token() {
        let claims = verify_and_extract(
            header(), payload(), kid(), rsa_hint(), registry_with_google_key(),
        );
        assert!(claims.exp == 1790257359);
        assert!(claims.nonce == 0xREDACTED_NONCE);
        let expected = identity(
            @"https://accounts.google.com",
            @"REDACTED_CLIENT_ID",
            @"REDACTED_SUB",
        );
        assert!(claims.identity == expected);
    }

    #[test]
    #[should_panic(expected: 'BAD_SIGNATURE')]
    fn rejects_tampered_payload() {
        verify_and_extract(
            header(), payload_head() + "1", kid(), rsa_hint(), registry_with_google_key(),
        );
    }

    #[test]
    #[should_panic(expected: 'UNKNOWN_KID')]
    fn rejects_unknown_kid() {
        let owner: ContractAddress = 'owner'.try_into().unwrap();
        let class = declare("JwkRegistry").unwrap().contract_class();
        let (empty_registry, _) = class.deploy(@array![owner.into()]).unwrap();
        verify_and_extract(header(), payload(), kid(), rsa_hint(), empty_registry);
    }
}
