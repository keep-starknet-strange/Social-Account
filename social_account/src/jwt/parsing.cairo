use super::types::JwtPayload;

pub fn extract_claims(json: ByteArray) -> JwtPayload {
    let s = to_bytes(@json);
    let mut i: usize = 0;
    assert(byte(s, i) == '{', 'BAD_PAYLOAD');
    i += 1;

    let mut iss: Option<ByteArray> = None;
    let mut aud: Option<ByteArray> = None;
    let mut sub: Option<ByteArray> = None;
    let mut nonce: Option<ByteArray> = None;
    let mut exp: Option<u64> = None;

    loop {
        assert(byte(s, i) == '"', 'BAD_PAYLOAD');
        i += 1;
        let mut key: felt252 = 0;
        let mut key_len: usize = 0;
        loop {
            let b = byte(s, i);
            i += 1;
            if b == '"' {
                break;
            }
            assert(b != '\\', 'BAD_PAYLOAD');
            if key_len < 31 {
                key = key * 256 + b.into();
            }
            key_len += 1;
        }
        if key_len > 31 {
            key = 0;
        }
        assert(byte(s, i) == ':', 'BAD_PAYLOAD');
        i += 1;

        // Value.
        let wanted = key == 'iss' || key == 'aud' || key == 'sub' || key == 'nonce';
        if byte(s, i) == '"' {
            i += 1;
            let value = read_string(s, ref i, wanted);
            if key == 'iss' {
                assert(iss.is_none(), 'BAD_PAYLOAD');
                iss = Some(value);
            } else if key == 'aud' {
                assert(aud.is_none(), 'BAD_PAYLOAD');
                aud = Some(value);
            } else if key == 'sub' {
                assert(sub.is_none(), 'BAD_PAYLOAD');
                sub = Some(value);
            } else if key == 'nonce' {
                assert(nonce.is_none(), 'BAD_PAYLOAD');
                nonce = Some(value);
            } else {
                assert(key != 'exp', 'BAD_PAYLOAD');
            }
        } else {
            assert(byte(s, i) != '{' && byte(s, i) != '[', 'NOT_FLAT');
            assert(!wanted, 'BAD_PAYLOAD');
            let is_exp = key == 'exp';
            let mut n: u64 = 0;
            loop {
                let b = byte(s, i);
                if b == ',' || b == '}' {
                    break;
                }
                if is_exp {
                    assert(b >= '0' && b <= '9', 'BAD_PAYLOAD');
                    n = n * 10 + (b - '0').into();
                }
                i += 1;
            }
            if is_exp {
                assert(exp.is_none(), 'BAD_PAYLOAD');
                exp = Some(n);
            }
        }

        let b = byte(s, i);
        i += 1;
        if b == '}' {
            break;
        }
        assert(b == ',', 'BAD_PAYLOAD');
    }
    assert(i == s.len(), 'BAD_PAYLOAD');

    JwtPayload {
        iss: iss.expect('MISSING_CLAIM'),
        aud: aud.expect('MISSING_CLAIM'),
        sub: sub.expect('MISSING_CLAIM'),
        nonce: nonce.expect('MISSING_CLAIM'),
        exp: exp.expect('MISSING_CLAIM'),
    }
}

fn read_string(s: Span<u8>, ref i: usize, collect: bool) -> ByteArray {
    let mut out: ByteArray = Default::default();
    loop {
        let b = byte(s, i);
        i += 1;
        if b == '"' {
            break;
        }
        if b == '\\' {
            assert(!collect, 'BAD_PAYLOAD');
            // Skip the escaped byte. A `\uXXXX` escape leaves four plain hex bytes behind it,
            // which read as ordinary characters.
            i += 1;
            continue;
        }
        if collect {
            out.append_byte(b);
        }
    }
    out
}

fn byte(s: Span<u8>, i: usize) -> u8 {
    match s.get(i) {
        Some(b) => *b.unbox(),
        None => core::panic_with_felt252('BAD_PAYLOAD'),
    }
}

fn to_bytes(ba: @ByteArray) -> Span<u8> {
    let mut felts: Array<felt252> = array![];
    ba.serialize(ref felts);
    let mut felts = felts.span();
    let n_words: usize = (*felts.pop_front().unwrap()).try_into().unwrap();
    let mut out: Array<u8> = array![];
    for _ in 0..n_words {
        push_word(ref out, *felts.pop_front().unwrap(), 31);
    }
    let pending = *felts.pop_front().unwrap();
    let pending_len: usize = (*felts.pop_front().unwrap()).try_into().unwrap();
    push_word(ref out, pending, pending_len);
    out.span()
}

fn push_word(ref out: Array<u8>, word: felt252, len: usize) {
    let w: u256 = word.into();
    if len > 16 {
        push_bytes(ref out, w.high, len - 16);
        push_bytes(ref out, w.low, 16);
    } else {
        push_bytes(ref out, w.low, len);
    }
}

fn push_bytes(ref out: Array<u8>, x: u128, len: usize) {
    // Move the first wanted byte into the top byte of the u128, then peel one byte per round.
    let mut x = x;
    for _ in 0..(16 - len) {
        x = x * 256;
    }
    let top: NonZero<u128> = 0x1000000000000000000000000000000_u128.try_into().unwrap();
    for _ in 0..len {
        let (b, rem) = DivRem::div_rem(x, top);
        out.append(b.try_into().unwrap());
        x = rem * 256;
    }
}

#[cfg(test)]
mod tests {
    use super::extract_claims;

    /// The decoded payload of the token used in verification tests.
    fn google_payload() -> ByteArray {
        "{\"iss\":\"https://accounts.google.com\",\"azp\":\"REDACTED_CLIENT_ID\",\"aud\":\"REDACTED_CLIENT_ID\",\"sub\":\"REDACTED_SUB\",\"at_hash\":\"REDACTED_AT_HASH\",\"nonce\":\"0xREDACTED_NONCE\",\"iat\":1790253759,\"exp\":1790257359}"
    }

    #[test]
    fn reads_the_five_claims() {
        let p = extract_claims(google_payload());
        assert!(p.iss == "https://accounts.google.com");
        assert!(
            p.aud == "REDACTED_CLIENT_ID",
        );
        assert!(p.sub == "REDACTED_SUB");
        assert!(p.nonce == "0xREDACTED_NONCE");
        assert!(p.exp == 1790257359);
    }

    #[test]
    fn steps_over_escapes_and_literals_in_other_fields() {
        // A display name that tries to smuggle a sub claim, then a boolean and a null.
        let p = extract_claims(
            "{\"name\":\"x,\\\"sub\\\":\\\"evil\\\"\",\"email_verified\":true,\"hd\":null,\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"0x1\",\"exp\":7}",
        );
        assert!(p.sub == "s");
        assert!(p.exp == 7);
    }

    #[test]
    #[should_panic(expected: 'MISSING_CLAIM')]
    fn rejects_a_missing_claim() {
        extract_claims("{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"exp\":7}");
    }

    #[test]
    #[should_panic(expected: 'NOT_FLAT')]
    fn rejects_a_nested_value() {
        extract_claims("{\"iss\":{\"x\":1}}");
    }

    #[test]
    #[should_panic(expected: 'BAD_PAYLOAD')]
    fn rejects_an_escape_inside_a_claim() {
        extract_claims(
            "{\"iss\":\"a\\\"b\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"0x1\",\"exp\":7}",
        );
    }
}
