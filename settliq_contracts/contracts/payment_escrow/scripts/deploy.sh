#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
CONTRACTS_ROOT="${REPO_ROOT}/settliq_contracts"
ENV_EXAMPLE_PATH="${CONTRACTS_ROOT}/contracts/payment_escrow/scripts/deployed-contract-ids.env"
WASM_PATH="${WASM_PATH:-${CONTRACTS_ROOT}/target/wasm32v1-none/release/payment_escrow.wasm}"
NETWORK="${NETWORK:-testnet}"

case "$NETWORK" in
  testnet)
    RPC_URL="${SOROBAN_RPC_URL:-https://soroban-testnet.stellar.org}"
    NETWORK_PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
    ENV_KEY="SOROBAN_ESCROW_CONTRACT_ID_TESTNET"
    ;;
  mainnet)
    RPC_URL="${SOROBAN_RPC_URL:-https://mainnet.sorobanrpc.com}"
    NETWORK_PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Public Global Stellar Network ; September 2015}"
    ENV_KEY="SOROBAN_ESCROW_CONTRACT_ID_MAINNET"
    ;;
  *)
    echo "Unsupported NETWORK: ${NETWORK}. Use testnet or mainnet." >&2
    exit 1
    ;;
esac

if [[ -z "${STELLAR_SOURCE_ACCOUNT_SECRET:-}" ]]; then
  echo "Missing STELLAR_SOURCE_ACCOUNT_SECRET." >&2
  exit 1
fi

if [[ ! -f "${WASM_PATH}" ]]; then
  echo "Escrow WASM not found at ${WASM_PATH}. Building..."
  # Build the Soroban contract to WebAssembly (issue #88: fixed cargo command)
  cargo build --manifest-path "${CONTRACTS_ROOT}/contracts/payment_escrow/Cargo.toml" \
    --target wasm32v1-none --release
fi

echo "Deploying escrow contract to ${NETWORK}..."
CONTRACT_ID="$(
  stellar contract deploy \
    --wasm "${WASM_PATH}" \
    --source-account "${STELLAR_SOURCE_ACCOUNT_SECRET}" \
    --rpc-url "${RPC_URL}" \
    --network-passphrase "${NETWORK_PASSPHRASE}" | tr -d '\r'
)"

if [[ -z "${CONTRACT_ID}" ]]; then
  echo "Deployment did not return a contract ID." >&2
  exit 1
fi

echo "Deployed contract ID: ${CONTRACT_ID}"

update_env_key() {
  local key="$1"
  local value="$2"
  local file="$3"

  touch "${file}"

  # Use grep instead of rg for portability (issue #88: removed ripgrep dependency)
  if grep -q "^${key}=" "${file}"; then
    sed -i.bak "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    printf '\n%s=%s\n' "${key}" "${value}" >> "${file}"
  fi

  rm -f "${file}.bak"
}

update_env_key "${ENV_KEY}" "${CONTRACT_ID}" "${ENV_EXAMPLE_PATH}"
update_env_key "SOROBAN_ESCROW_CONTRACT_ID" "${CONTRACT_ID}" "${ENV_EXAMPLE_PATH}"

echo "Recorded ${ENV_EXAMPLE_PATH} with ${ENV_KEY} and SOROBAN_ESCROW_CONTRACT_ID."
echo "Copy these values into the backend repo's .env before redeploying/restarting it."

CONTRACT_ID="${CONTRACT_ID}" ESCROW_CONTRACT_ID="${CONTRACT_ID}" NETWORK="${NETWORK}" \
  "${SCRIPT_DIR}/init.sh"

echo "Deploy + init complete for ${NETWORK}."
