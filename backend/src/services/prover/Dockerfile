FROM ghcr.io/starknet-innovation/snip-36-prover-backend:latest
ENV PROVER_IP=0.0.0.0 \
    PROVER_PORT=9900 \
    SKIP_FEE_FIELD_VALIDATION=true \
    PREFETCH_STATE=false
ENTRYPOINT ["/app/deps/sequencer/target/release/starknet_transaction_prover"]
