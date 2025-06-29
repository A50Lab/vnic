# VietChain KYC DID JavaScript Client

A simple JavaScript client for testing DID (Decentralized Identifier) registration on VietChain.

## Prerequisites

1. **Node.js** (>= 18.0.0)
2. **VietChain node running locally**:
   ```bash
   ignite chain serve
   ```

## Setup

1. **Install dependencies**:
   ```bash
   cd client-js
   npm install
   ```

2. **Configure your test account**:
   - Edit `did-client.js`
   - Replace the `MNEMONIC` in CONFIG with your test account mnemonic
   - Or use the default test mnemonic for development

## Usage

### Check Chain Status
```bash
node did-client.js status
```

- Funding with: `Bash(vnicd tx bank send alice vnic19rl-{TARGET} 1000stake --yes)`

### Register a New DID
```bash
# Generate random DID
node did-client.js register

# Register with custom ID
node did-client.js register did:vnic:my-custom-id
```

### Query Existing DID
```bash
node did-client.js query did:vnic:my-custom-id
```

### Show Help
```bash
node did-client.js help
```

## Configuration

Edit the `CONFIG` object in `did-client.js`:

```javascript
const CONFIG = {
    RPC_ENDPOINT: 'http://localhost:26657',      // Tendermint RPC
    REST_ENDPOINT: 'http://localhost:1317',      // Cosmos REST API  
    CHAIN_ID: 'vnic',                            // Chain identifier
    MNEMONIC: 'your-test-mnemonic-here',         // Test account
    GAS_PRICE: '0.025uvnic',                     // Gas price
};
```

## Example Output

### Successful DID Registration
```
🔧 Initializing VietChain KYC Client...
📍 Using address: vnic1abc123...
✅ Client initialized successfully
🆔 Registering new DID: did:vnic:1699123456-abc123
📤 Broadcasting transaction...
✅ DID registered successfully!
   Transaction Hash: A1B2C3D4E5F6...
   Block Height: 145
   Gas Used: 89234/120000

🔍 Querying identity: did:vnic:1699123456-abc123
📋 Identity Information:
   ID: did:vnic:1699123456-abc123
   Creator: vnic1abc123...
   State: 12345678901234567890...
   KYC Level: 0
   Claims Root: 0
   Revocation Root: 0
   Roots Tree Root: 0
```

### Identity Query
```
🔍 Querying identity: did:vnic:existing-id
📋 Identity Information:
   ID: did:vnic:existing-id
   Creator: vnic1def456...
   State: 98765432109876543210...
   KYC Level: 2
   Claims Root: 11111111111111111111...
   Revocation Root: 0
   Roots Tree Root: 22222222222222222222...
   Attributes:
     country: VN
     age_verification: true
```

## Testing Flow

1. **Start your chain**:
   ```bash
   ignite chain serve
   ```

2. **Check status**:
   ```bash
   node did-client.js status
   ```

3. **Register DID**:
   ```bash
   node did-client.js register did:vnic:test-identity-1
   ```

4. **Query DID**:
   ```bash
   node did-client.js query did:vnic:test-identity-1
   ```

## Troubleshooting

### Chain Not Accessible
- Ensure VietChain is running: `ignite chain serve`
- Check RPC endpoint is accessible: `curl http://localhost:26657/status`

### Transaction Failures
- Check account has sufficient balance for gas fees
- Verify identity ID doesn't already exist
- Check transaction logs for detailed error messages

### Module Not Found
- Ensure KYC module is properly installed in your chain
- Verify module name matches your chain configuration

## Integration with Development

This client can be integrated into your development workflow:

1. **Automated Testing**: Use in CI/CD pipelines
2. **Load Testing**: Create multiple identities for testing
3. **Integration Testing**: Test KYC flow end-to-end
4. **Development**: Quick DID creation during development
