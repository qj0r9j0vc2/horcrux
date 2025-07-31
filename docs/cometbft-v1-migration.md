# CometBFT v1.0 Protocol Support

Horcrux now supports both the legacy (v0.38 and earlier) and v1.0 CometBFT privval protocols. This document explains how to configure Horcrux for CometBFT v1.0 compatibility.

## Background

CometBFT v1.0 introduced breaking changes to the privval (private validator) protocol. The main changes include:

1. **Package namespace migration**: From `tendermint.privval` to `cometbft.privval.v1`
2. **Public key encoding changes**: From wrapped `PublicKey` message to raw bytes + type string
3. **New message types**: Added `SignBytesRequest/Response` for arbitrary byte signing
4. **New fields**: Added `skip_extension_signing` to `SignVoteRequest`

## Configuration

To enable CometBFT v1.0 protocol support, add the `protocolVersion` field to your Horcrux configuration:

```yaml
# For CometBFT v1.0+
protocolVersion: v1

# For CometBFT v0.38 and earlier (default)
protocolVersion: legacy
```

If `protocolVersion` is not specified, Horcrux defaults to `legacy` for backward compatibility.

## Example Configuration

See [cometbft-v1-config-example.yaml](cometbft-v1-config-example.yaml) for a complete configuration example.

## Migration Steps

1. **Verify your CometBFT version**: Ensure your chain is running CometBFT v1.0 or later
2. **Update Horcrux configuration**: Add `protocolVersion: v1` to your config file
3. **Restart Horcrux**: The new protocol will be used automatically

## Troubleshooting

### Error: "can't get pubkey: encoding: unsupported key"
This error indicates a protocol mismatch. Ensure:
- Your chain is running CometBFT v1.0+
- Your Horcrux config has `protocolVersion: v1`

### Error: "unknown message type"
This suggests the wrong protocol version is configured. Check your CometBFT version and adjust `protocolVersion` accordingly.

## Compatibility Matrix

| CometBFT Version | Horcrux protocolVersion |
|-----------------|------------------------|
| v0.34.x - v0.38.x | `legacy` (default) |
| v1.0.0+ | `v1` |

## Technical Details

The implementation provides a dual-protocol architecture:
- `LegacyProtocol`: Handles v0.38 and earlier protocol
- `V1Protocol`: Handles v1.0 protocol
- Protocol selection is based on configuration
- Both protocols convert messages to a common internal format for signing

This ensures compatibility while maintaining a clean separation between protocol versions.