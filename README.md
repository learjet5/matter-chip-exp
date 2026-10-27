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
commissioner/controller. Every credential is embedded as a standard padded
Base64 string.
Certificate fields accept either X.509 DER or Matter TLV certificate bytes and
are converted to X.509 DER internally. P-256 public and private key fields
encode a raw 65-byte uncompressed point and a raw 32-byte scalar, respectively.
Provide exactly one 16-byte IPK field: `epoch_ipk` or `operational_ipk`. The SDK
derives the operational IPK from an epoch IPK and the compressed fabric ID;
chip-exp injects an already-derived operational IPK directly.

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
  "epoch_ipk": "<Base64 raw 16-byte epoch IPK>"
}
```

Replace `epoch_ipk` with `operational_ipk` when only the derived operational IPK
is available.

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

ICAC mode uses an existing RCAC/ICAC chain, the ICAC key pair, and the fabric
IPK to generate NOCs:

```json
{
  "mode": "icac",
  "rcac": "<Base64 X.509 DER or Matter TLV certificate>",
  "icac": "<Base64 X.509 DER or Matter TLV certificate>",
  "icac_public_key": "<Base64 raw 65-byte P-256 public key>",
  "icac_private_key": "<Base64 raw 32-byte P-256 private key>",
  "fabric_id": "0x1234",
  "controller_nodeid": "0x112233",
  "controller_cat": ["0xFFFFFFFD00010001"],
  "epoch_ipk": "<Base64 raw 16-byte epoch IPK>"
}
```

`fabric_id` identifies the fabric used by both chip-exp's dynamically generated
controller NOC and every target NOC it issues. `controller_nodeid` and
`controller_cat` define the Node ID and CATs in chip-exp's own controller NOC.
IDs and CATs are strings containing decimal or `0x`-prefixed hexadecimal
integers. CATs may use either their raw 32-bit form (`0x00010001`) or their
64-bit ACL subject form (`0xFFFFFFFD00010001`). Use an empty `controller_cat`
array when the controller needs no CAT.

Replacing `epoch_ipk` with `operational_ipk` can instead initialize the local commissioner
for an existing fabric. It cannot commission a new device because `AddNOC` requires
the epoch IPK and the derivation is not reversible.

Once initialized, chip-exp can use its generated controller NOC to establish a
CASE session with a device already on the configured fabric. For example:

```shell
./build/chip-exp onoff toggle <device_node_id> <endpoint_id> \
  --credentials credentials/icac.json \
  --storage-directory .local/icac-state
```

Normal pairing commands use the configured issuer automatically. `--target-cat`
sets CATs in the NOC issued to the device being commissioned; it does not change
the controller CATs stored in the manifest:

```shell
./build/chip-exp pairing code <device_node_id> <pairing_code> \
  --credentials credentials/icac.json \
  --target-cat 0xFFFFFFFD00030001 \
  --storage-directory .local/icac-state
```

To sign a NOC for a previously obtained NOCSR directly, use
`pairing issue-noc-chain`:

```shell
./build/chip-exp pairing issue-noc-chain <nocsr_elements_hex> <device_node_id> \
  --credentials credentials/icac.json \
  --target-cat 0xFFFFFFFD00030001 \
  --storage-directory .local/icac-state
```

`--target-cat` accepts either the raw 32-bit CAT or its 64-bit ACL subject form.
The issuer checks that the configured ICAC key pair matches the ICAC certificate
and gives generated NOCs the same validity interval as the ICAC.

## Build

`chip-exp` is currently based on Matter SDK v1.6.0.0. Point its local SDK link
at a clean v1.6.0.0 checkout with the host-platform submodules initialized:

```shell
ln -sfn /path/to/connectedhomeip-1.6.0.0 chip-exp/third_party/connectedhomeip
mkdir -p build
cd build
/path/to/connectedhomeip-1.6.0.0/scripts/configure \
  --project=/path/to/matter-chip-exp/chip-exp
./ninja-build
```

The single build command produces `build/chip-exp`, the stock `build/chip-tool`,
and `build/chip-cert`. To rebuild only one binary, pass its name to
`./ninja-build`. No changes to the Matter SDK source tree are required. The
local SDK symlink is ignored by Git; the tracked `chip-exp/build_overrides`
symlink resolves through it.
