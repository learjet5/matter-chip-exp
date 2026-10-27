# matter-chip-exp

From chip-tool to chip-exp.

## Why chip-exp

The stock Matter `chip-tool` is designed to generate a commissioner identity on
demand. It persistently reuses its RCAC and ICAC issuer credentials, but dynamically
creates a new operational key pair and issues a corresponding NOC whenever it
initializes a commissioner. As a result, it does not provide a convenient
workflow for assembling an existing controller NOC, its matching operational
private key, and the fabric IPK into a controller that can establish CASE
sessions.

`chip-exp` extends this workflow for security research by allowing existing
credentials to be imported and used together. This is an extension to
`chip-tool`; the underlying Matter SDK already provides the low-level controller
initialization primitives.

## Credential modes

Pass `--credentials <manifest.json>` to any command that initializes a
commissioner. Every credential is embedded as a standard padded Base64 string.
Certificate fields accept either X.509 DER or Matter TLV certificate bytes and
are converted to X.509 DER internally. P-256 public and private key fields
encode a raw 65-byte uncompressed point and a raw 32-byte scalar, respectively.
The IPK field encodes 16 raw bytes.

Keep manifests outside the repository, or under the ignored `credentials/`
directory. `chip-exp` logs the selected mode but never logs credential contents.

### NOC mode

NOC mode assembles an existing controller identity from its certificate
chain, operational key pair, and fabric IPK:

```json
{
  "mode": "noc",
  "rcac": "<Base64 X.509 DER or Matter TLV certificate>",
  "icac": "<Base64 X.509 DER or Matter TLV certificate>",
  "noc": "<Base64 X.509 DER or Matter TLV certificate>",
  "operational_public_key": "<Base64 raw 65-byte P-256 public key>",
  "operational_private_key": "<Base64 raw 32-byte P-256 private key>",
  "ipk": "<Base64 raw 16-byte IPK>"
}
```

For example, the following command uses the imported identity to establish a
CASE session and read an attribute:

```shell
./build/chip-exp onoff read on-off 1 1 \
  --credentials credentials/noc.json \
  --storage-directory .local/noc-state
```

The operational public key must match the NOC. The SDK validates the imported
certificate chain before installing the controller fabric. This mode does not
have a CA signing key, so it can control devices already on the fabric but
cannot issue new NOCs or commission another device.

### ICAC mode

ICAC mode uses an existing ICAC and its key pair to issue NOCs. The RCAC,
ICAC, and IPK are returned with each generated chain:

```json
{
  "mode": "icac",
  "rcac": "<Base64 X.509 DER or Matter TLV certificate>",
  "icac": "<Base64 X.509 DER or Matter TLV certificate>",
  "icac_public_key": "<Base64 raw 65-byte P-256 public key>",
  "icac_private_key": "<Base64 raw 32-byte P-256 private key>",
  "ipk": "<Base64 raw 16-byte IPK>"
}
```

Normal pairing commands use the configured issuer automatically. The local
commissioner node ID can be selected with `--commissioner-nodeid`, and CATs for
the commissioned node can be supplied with the existing `--case-auth-tags`
option:

```shell
./build/chip-exp pairing code 0x12344321 MT:ONBOARDING_CODE \
  --credentials credentials/icac.json \
  --commissioner-nodeid 0x112233 \
  --case-auth-tags 0x00010001,0x00020001 \
  --storage-directory .local/icac-state
```

To sign a NOC for a previously obtained NOCSR directly, use
`pairing issue-noc-chain`:

```shell
./build/chip-exp pairing issue-noc-chain NOCSR_ELEMENTS_HEX 0x12344321 \
  --credentials credentials/icac.json \
  --case-auth-tags 0x00010001,0x00020001 \
  --storage-directory .local/icac-state
```

CAT values are comma-separated 32-bit integers. The issuer checks that the
configured ICAC key pair matches the ICAC certificate and gives generated NOCs
the same validity interval as the ICAC.

## Build

`chip-exp` is currently based on Matter SDK v1.6.0.0. Point its local SDK link
at a clean v1.6.0.0 checkout with the host-platform submodules initialized:

```shell
ln -sfn /path/to/connectedhomeip-1.6.0.0 chip-exp/third_party/connectedhomeip
mkdir -p build
cd build
/path/to/connectedhomeip-1.6.0.0/scripts/configure \
  --project=/path/to/matter-chip-exp/chip-exp
./ninja-build chip-exp
```

The resulting binary is `build/chip-exp`. No changes to the Matter SDK source
tree are required. The local SDK symlink is ignored by Git; the tracked
`chip-exp/build_overrides` symlink resolves through it.
