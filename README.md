# Design
```mermaid
---
config:
  theme: redux-dark-color
  look: classic
---
sequenceDiagram
  autonumber
  participant C as Client<br/>app + SDK
  participant G as Google<br/>OAuth · JWKS
  participant B as Backend<br/>bun api
  participant P as Prover<br/>SNIP-36
  participant S as Starknet<br/>Sepolia RPC + Sequencer

  Note over C: app: random keypair (new_pubkey), kept in the tab<br/>SDK: random nonce
  C ->> G: login(nonce)
  G -->> C: JWT { iss, aud, sub, exp, nonce, ... }
  Note over C: first JWT is only used to learn sub<br/>identity = h(iss, aud, sub)<br/>contract_address = udc_address(class, salt = identity, from_zero, [identity])
  C ->> S: get_public_key(contract_address)
  alt deployed
    S -->> C: curr_pubkey (0 right after deploy)
  else not deployed
    S -->> C: contract not found
    Note over C: curr_pubkey = 0
  end
  Note over C: nonce = h(contract_address, new_pubkey, curr_pubkey)
  C ->> G: silent login(nonce, prompt=none), reuses the Google session
  G -->> C: JWT { ..., nonce }

  opt not deployed and the SDK was given a deploy hook (user pays)
    C ->> S: user's own account invoke: UDC.deployContract(class, salt = identity, from_zero, [identity])
    C <<->> S: wait for tx
  end
  Note over C: signature = sign(new_privkey, accept_ownership(contract_address, curr_pubkey))
  C ->> B: /api/recover { jwt, contract_address, new_pubkey, signature }
  Note over B: verify JWT (Google JWKS, aud)<br/>identity → contract_address, must match the one sent
  opt still not deployed (backend pays)
    B ->> S: relayer invoke: UDC.deployContract(class, salt = identity, from_zero, [identity])
    B <<->> S: wait for tx
  end
  Note over B: check nonce against get_public_key<br/>extract jwt header.kid, rsa_hint (garaga)
  B ->> P: prove_jwt({ header, payload, kid, rsa_hint, new_pubkey }) on contract_address, sent by the prover account
  Note over P: virtual block: the JWT never touches the chain
  P -->> B: { proof, proof_facts, L2→L1 [contract_address, identity, new_pubkey, curr_pubkey] }
  B ->> S: relayer invoke: recover(new_pubkey, signature) + proof, proof_facts
  Note over S: recover checks the facts, then set_public_key(new_pubkey, signature)
  B <<->> S: wait for tx
  B -->> C: { contract_address, identity, tx_hash }
```

## Notes

- **Who pays.** The UDC address depends only on class, salt and calldata, so anyone may deploy. The SDK takes an optional `deploy` hook for the user's own account; without it the backend's relayer deploys inside `/recover`. The relayer also submits `recover`. It is a separate funded account, not the registry owner.
- **The signature.** OpenZeppelin's `set_public_key` requires the new key to sign `accept_ownership(contract_address, curr_pubkey)`. Only the client holds the new private key, so the client signs and the backend forwards it.
- **POC escape hatch, `PROVER_MODE=onchain`.** The prover cannot run garaga's builtins yet. In this mode the relayer sends `prove_jwt` as a real transaction instead of proving it. The contract records `h(new_pubkey, curr_pubkey)` and a `recover` without proof facts consumes that record once. Same checks, but the JWT and the Google `sub` become public calldata. The contract refuses this path on `SN_MAIN`.
