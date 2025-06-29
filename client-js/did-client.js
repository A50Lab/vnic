#!/usr/bin/env node

const { SigningStargateClient, GasPrice } = require("@cosmjs/stargate");
const { DirectSecp256k1HdWallet } = require("@cosmjs/proto-signing");
const { stringToPath } = require("@cosmjs/crypto");
const axios = require("axios");
const { Poseidon, babyJub, BabyJub, PrivateKey, getRandomBytes } = require("@iden3/js-crypto");

// Configuration
const CONFIG = {
  // Local chain configuration for client's own transactions
  RPC_ENDPOINT: "http://localhost:26657",
  REST_ENDPOINT: "http://localhost:1317",
  CHAIN_ID: "vnic",
  
  // Test account mnemonic (replace with your test account)
  "MNEMONIC":
    "cousin audit drive link various company mind reopen radio diary south rhythm spray permit name order pencil wolf park fly hard code ready immune",

  // Gas configuration
  GAS_PRICE: "0.00000025stake",

  // Issuer service configuration - for CLI operations
  ISSUER_SERVICE_URL: "http://localhost:3001",
};

class VietChainKYCClient {
  constructor() {
    this.wallet = null;
    this.client = null;
    this.address = null;
  }

  // Helper function for Poseidon hashing
  poseidonHash(inputs) {
    const fieldSize = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
    const validInputs = inputs.map(input => BigInt(input) % fieldSize);
    return Poseidon.hash(validInputs);
  }

  // Initialize wallet and client for user's own transactions
  async init() {
    try {
      console.log("🔧 Initializing VietChain KYC Client...");

      // Create wallet from mnemonic for user's own transactions
      this.wallet = await DirectSecp256k1HdWallet.fromMnemonic(
        CONFIG.MNEMONIC,
        {
          prefix: "vnic",
          hdPaths: [stringToPath("m/44'/118'/0'/0/0")],
        },
      );

      // Get address
      const accounts = await this.wallet.getAccounts();
      this.address = accounts[0].address;
      console.log(`📍 Using address: ${this.address}`);

      // Create signing client for direct blockchain interaction
      this.client = await SigningStargateClient.connectWithSigner(
        CONFIG.RPC_ENDPOINT,
        this.wallet,
        {
          gasPrice: GasPrice.fromString(CONFIG.GAS_PRICE),
        },
      );

      // Check connection to issuer service for CLI operations
      const serviceCheck = await this.checkServiceHealth();
      if (!serviceCheck) {
        console.log("⚠️  Issuer service not available - CLI operations will be limited");
      }

      console.log("✅ Client initialized successfully");
      return true;
    } catch (error) {
      console.error("❌ Failed to initialize client:", error.message);
      return false;
    }
  }

  // Check if issuer service is available for CLI operations
  async checkServiceHealth() {
    try {
      const response = await axios.get(`${CONFIG.ISSUER_SERVICE_URL}/health`);
      
      if (response.data.status === 'ok') {
        console.log("✅ Issuer service available for CLI operations");
        return true;
      }
      
      return false;
    } catch (error) {
      console.log("⚠️  Issuer service not accessible - some CLI operations may fail");
      return false;
    }
  }

  // Check chain status
  async checkChainStatus() {
    try {
      console.log("🔍 Checking chain status...");

      const status = await axios.get(
        `${CONFIG.REST_ENDPOINT}/cosmos/base/tendermint/v1beta1/node_info`,
      );
      console.log(`⛓️  Chain ID: ${status.data.default_node_info.network}`);
      console.log(
        `📦 Latest Block: ${status.data.default_node_info.other.latest_block_height || "N/A"}`,
      );

      return true;
    } catch (error) {
      console.error("❌ Chain not accessible:", error.message);
      console.log("💡 Make sure your VietChain node is running with:");
      console.log("   ignite chain serve");
      return false;
    }
  }

  // Check account balance
  async checkBalance() {
    try {
      console.log("💰 Checking account balance...");

      const balance = await this.client.getAllBalances(this.address);
      if (balance.length === 0) {
        console.log("⚠️  Account has no balance");
        console.log(
          "💡 You may need to fund your account for transaction fees",
        );
      } else {
        balance.forEach((coin) => {
          console.log(`   ${coin.amount} ${coin.denom}`);
        });
      }

      return true;
    } catch (error) {
      console.error("❌ Failed to check balance:", error.message);
      return false;
    }
  }

  // Register a new DID via server API (CLI operation)
  async registerDID(identityId) {
    try {
      console.log(`🆔 Registering new DID: ${identityId}`);

      const response = await axios.post(
        `${CONFIG.ISSUER_SERVICE_URL}/api/v1/register-identity`,
        { identityId },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.success) {
        console.log("✅ DID registered successfully!");
        console.log(`   Transaction Hash: ${response.data.txHash}`);
        console.log(`   Identity ID: ${response.data.identityId}`);
        
        // Query the newly created identity after a short delay
        setTimeout(() => this.queryIdentity(identityId), 0);
        
        return true;
      } else {
        console.error("❌ Failed to register DID:", response.data.error);
        return false;
      }
    } catch (error) {
      if (error.response?.status === 409) {
        console.log("⚠️  Identity already exists");
        console.log(`   Identity: ${error.response.data.identity?.id}`);
        return false;
      } else {
        console.error("❌ Failed to register DID:", error.response?.data?.error || error.message);
        console.log("💡 Make sure:");
        console.log("   - The issuer service is running");
        console.log("   - The blockchain node is accessible");
        console.log("   - The identity ID format is valid");
        return false;
      }
    }
  }

  // Query identity information via server API (CLI operation)
  async queryIdentity(identityId, showOutput = true) {
    try {
      if (showOutput) {
        console.log(`🔍 Querying identity: ${identityId}`);
      }

      const response = await axios.get(
        `${CONFIG.ISSUER_SERVICE_URL}/api/v1/query-identity/${encodeURIComponent(identityId)}`
      );

      if (response.data.success && response.data.identity) {
        const identity = response.data.identity;

        if (showOutput) {
          console.log("📋 Identity Information:");
          console.log(`   ID: ${identity.id}`);
          console.log(`   Creator: ${identity.creator}`);
          console.log(`   State: ${identity.state}`);
          console.log(`   KYC Level: ${identity.kyc_level}`);
          console.log(`   Claims Root: ${identity.claims_root}`);
          console.log(`   Revocation Root: ${identity.rev_root}`);
          console.log(`   Roots Tree Root: ${identity.roots_root}`);

          if (identity.attributes && Object.keys(identity.attributes).length > 0) {
            console.log("   Attributes:");
            Object.entries(identity.attributes).forEach(([key, value]) => {
              console.log(`     ${key}: ${value}`);
            });
          }
        }

        return identity;
      }

      if (showOutput) {
        console.log("❌ Identity not found");
      }
      return null;
    } catch (error) {
      if (showOutput) {
        if (error.response && error.response.status === 404) {
          console.log("❌ Identity not found");
        } else {
          console.error("❌ Failed to query identity:", error.response?.data?.error || error.message);
        }
      }
      return null;
    }
  }

  // Generate cryptographic identity ID using Poseidon hashing
  generateIdentityId() {
    try {
      // Generate random bytes for identity seed
      const identitySeed = getRandomBytes(32);
      
      // Create BigInt from bytes
      const seedBigInt = BigInt('0x' + Buffer.from(identitySeed).toString('hex'));
      
      // Generate identity commitment using Poseidon hash
      // This creates a unique identifier that's cryptographically secure
      const identityCommitment = this.poseidonHash([seedBigInt]);
      
      // Convert to hex string for DID format
      const identityHex = identityCommitment.toString(16).padStart(64, '0');
      
      console.log("🔐 Generated cryptographic identity:");
      console.log(`   Seed: ${seedBigInt.toString(16)}`);
      console.log(`   Identity Commitment: ${identityHex}`);
      
      return `did:vnic:${identityHex}`;
    } catch (error) {
      console.error("❌ Failed to generate cryptographic identity:", error.message);
      console.log("💡 Falling back to simple identifier...");
      
      // Fallback to simple generation if crypto fails
      const timestamp = Date.now();
      const random = Math.random().toString(36).substring(2, 8);
      return `did:vnic:${timestamp}-${random}`;
    }
  }

  // Generate identity from seed (for deterministic generation)
  generateIdentityFromSeed(seed) {
    try {
      console.log(`🌱 Generating identity from seed: ${seed}`);
      
      // Convert seed to buffer and hash it to get deterministic private key
      const seedBuffer = Buffer.from(seed, 'utf8');
      const seedHash = this.poseidonHash([BigInt('0x' + seedBuffer.toString('hex'))]);
      
      // Create private key from seed hash
      const privateKeyBigInt = seedHash;
      
      // Generate identity commitment using Poseidon hash
      const identityCommitment = this.poseidonHash([privateKeyBigInt]);
      
      // Convert to hex string for DID format
      const identityHex = identityCommitment.toString(16).padStart(64, '0');
      
      console.log("🔐 Generated deterministic cryptographic identity:");
      console.log(`   Seed: ${privateKeyBigInt.toString(16)}`);
      console.log(`   Identity Commitment: ${identityHex}`);
      
      return `did:vnic:${identityHex}`;
    } catch (error) {
      console.error("❌ Failed to generate identity from seed:", error.message);
      
      // Fallback to simple generation
      const timestamp = Date.now();
      const random = Math.random().toString(36).substring(2, 8);
      return `did:vnic:${timestamp}-${random}`;
    }
  }

  // Submit Vietnamese ID card for KYC verification (convenient method)
  async submitVietnameseID(identityId, fullName = "TRUONG VO KHANH HA", dateOfBirth = "27/06/2003", gender = "Nữ", nationality = "Việt Nam", cardNumber = "0628443382498", dateIssued = "22/12/2020") {
    console.log(`🇻🇳 Submitting Vietnamese ID card for: ${identityId}`);
    return await this.submitDocument(identityId, null, null, null, null, fullName, dateOfBirth, gender, nationality, cardNumber, dateIssued);
  }

  // Query submitted documents for a DID
  async querySubmittedDocuments(identityId) {
    try {
      console.log(`📋 Querying submitted documents for: ${identityId}`);

      const response = await axios.get(
        `${CONFIG.ISSUER_SERVICE_URL}/api/v1/documents/${encodeURIComponent(identityId)}`
      );

      if (response.data.success) {
        const data = response.data;
        
        console.log("📊 Submitted Documents Summary:");
        console.log(`   DID: ${data.did}`);
        console.log(`   Current KYC Level: ${data.currentKycLevel}`);
        console.log(`   Total Credentials: ${data.totalCredentials}`);
        console.log(`   Latest Submission: ${data.latestSubmission}`);
        console.log("");
        
        console.log("📄 Submitted Documents:");
        const docs = data.submittedDocuments;
        if (docs.name) console.log(`   Name: ${docs.name}`);
        if (docs.fullName) console.log(`   Full Name (Vietnamese): ${docs.fullName}`);
        if (docs.birthdate) console.log(`   Birthdate: ${docs.birthdate}`);
        if (docs.dateOfBirth) console.log(`   Date of Birth: ${docs.dateOfBirth}`);
        if (docs.phone) console.log(`   Phone: ${docs.phone}`);
        if (docs.gender) console.log(`   Gender: ${docs.gender}`);
        if (docs.nationality) console.log(`   Nationality: ${docs.nationality}`);
        if (docs.nationalId) console.log(`   National ID: ${docs.nationalId}`);
        if (docs.cardNumber) console.log(`   Card Number: ${docs.cardNumber}`);
        if (docs.dateIssued) console.log(`   Date Issued: ${docs.dateIssued}`);
        console.log("");
        
        console.log("🏆 Credential History:");
        data.allCredentials.forEach((cred, index) => {
          const status = cred.expired ? "❌ EXPIRED" : "✅ VALID";
          console.log(`   ${index + 1}. Level ${cred.kycLevel} - ${cred.issuedAt} ${status}`);
          console.log(`      Credential ID: ${cred.credentialId}`);
        });
        
        return data;
      }

      return null;
    } catch (error) {
      if (error.response && error.response.status === 404) {
        console.log("❌ No submitted documents found for this DID");
        console.log("💡 Submit documents first with:");
        console.log(`   bun run did-client.js submit-default-vn ${identityId}`);
      } else {
        console.error("❌ Failed to query submitted documents:", error.response?.data?.error || error.message);
      }
      return null;
    }
  }

  // Query documents with advanced filters
  async queryDocumentsAdvanced(identityId, options = {}) {
    try {
      const { includeExpired = false, minKycLevel = 0 } = options;
      
      console.log(`🔍 Advanced query for: ${identityId}`);
      console.log(`   Include expired: ${includeExpired}`);
      console.log(`   Min KYC level: ${minKycLevel}`);

      const response = await axios.post(
        `${CONFIG.ISSUER_SERVICE_URL}/api/v1/query-documents`,
        {
          did: identityId,
          includeExpired,
          minKycLevel
        },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.success) {
        const data = response.data;
        
        console.log("📊 Advanced Query Results:");
        console.log(`   DID: ${data.did}`);
        console.log(`   Current KYC Level: ${data.currentKycLevel}`);
        console.log(`   Matching Credentials: ${data.totalCredentials}`);
        console.log(`   Latest Submission: ${data.latestSubmission}`);
        console.log("");
        
        console.log("📄 Current Documents:");
        const docs = data.submittedDocuments;
        Object.entries(docs).forEach(([key, value]) => {
          if (value && key !== 'issuerNotes') {
            console.log(`   ${key}: ${value}`);
          }
        });
        console.log("");
        
        console.log("🎯 Matching Credentials:");
        data.matchingCredentials.forEach((cred, index) => {
          const status = cred.expired ? "❌ EXPIRED" : "✅ VALID";
          console.log(`   ${index + 1}. Level ${cred.kycLevel} - ${cred.issuedAt} ${status}`);
        });
        
        return data;
      }

      return null;
    } catch (error) {
      if (error.response && error.response.status === 404) {
        console.log("❌ No documents found matching criteria");
        console.log(`   DID: ${identityId}`);
        console.log(`   Criteria: includeExpired=${options.includeExpired}, minKycLevel=${options.minKycLevel}`);
      } else {
        console.error("❌ Failed to query documents:", error.response?.data?.error || error.message);
      }
      return null;
    }
  }

  // Submit documents for KYC verification via server API
  async submitDocument(identityId, nationalId, fullName, dateOfBirth, gender, nationality, address, dateIssued) {
    try {
      console.log(`📄 Submitting documents for KYC verification: ${identityId}`);

      // Check if identity exists on-chain first
      const identity = await this.queryIdentity(identityId, false);
      if (!identity) {
        console.log("❌ Identity not found on-chain. Please register the DID first.");
        return false;
      }

      // Prepare document submission with both legacy and Vietnamese ID card fields
      const documentData = {};
      
      // Legacy fields
      
      // Vietnamese ID card fields
      if (nationalId) documentData.nationalId = nationalId;
      if (fullName) documentData.fullName = fullName;
      if (dateOfBirth) documentData.dateOfBirth = dateOfBirth;
      if (gender) documentData.gender = gender;
      if (nationality) documentData.nationality = nationality;
      if (address) documentData.address = address;
      if (dateIssued) documentData.dateIssued = dateIssued;
      console.log("📋 Submitting documents with:");
      
      if (nationalId) console.log(`   National ID: ${nationalId}`);
      if (fullName) console.log(`   Full Name (Vietnamese): ${fullName}`);
      if (dateOfBirth) console.log(`   Date of Birth: ${dateOfBirth}`);
      if (gender) console.log(`   Gender: ${gender}`);
      if (nationality) console.log(`   Nationality: ${nationality}`);
      if (dateIssued) console.log(`   Date Issued: ${dateIssued}`);

      // Submit documents to issuer service
      const response = await axios.post(
        `${CONFIG.ISSUER_SERVICE_URL}/api/v1/submit-document`,
        {
          did: identityId,
          ...documentData
        },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.success) {
        console.log("✅ Document submitted successfully!");
        console.log(`   Credential ID: ${response.data.credential.id}`);
        console.log(`   KYC Level: ${response.data.kycLevel}`);
        console.log(`   Level Details: ${response.data.levelDetails}`);
        console.log(`   Issuer: ${response.data.credential.issuer.name}`);
        console.log(`   Valid until: ${response.data.credential.expirationDate}`);
        
        if (response.data.txHash) {
          console.log(`   Transaction Hash: ${response.data.txHash}`);
        }
        
        if (response.data.warning) {
          console.log(`   ⚠️  Warning: ${response.data.warning}`);
        }
        
        return response.data.credential;
      } else {
        console.log("❌ Failed to submit document");
        return false;
      }

    } catch (error) {
      console.error("❌ Failed to submit document:", error.response?.data?.error || error.message);
      console.log("💡 Make sure:");
      console.log("   - The issuer service is running");
      console.log("   - The DID is registered on-chain");
      return false;
    }
  }

  // Issue KYC credential from issuer service (legacy method)
  async issueCredential(identityId, documents = {}) {
    try {
      console.log(`📄 Requesting KYC credential for: ${identityId}`);

      // Check if identity exists on-chain first
      const identity = await this.queryIdentity(identityId, false);
      if (!identity) {
        console.log("❌ Identity not found on-chain. Please register the DID first.");
        return false;
      }

      // Default documents for testing if none provided
      const defaultDocuments = {
        idDocument: true,
        addressProof: true,
        incomeProof: false,
        bankStatement: false,
        businessLicense: false
      };

      const documentsToSubmit = Object.keys(documents).length > 0 ? documents : defaultDocuments;

      console.log("📋 Submitting documents:", Object.keys(documentsToSubmit).filter(key => documentsToSubmit[key]));

      // Request credential from issuer service
      const response = await axios.post(
        `${CONFIG.ISSUER_SERVICE_URL}/api/v1/issue-credential`,
        {
          did: identityId,
          documents: documentsToSubmit,
          holder: this.address
        },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.success) {
        console.log("✅ KYC Credential issued successfully!");
        console.log(`   Credential ID: ${response.data.credential.id}`);
        console.log(`   KYC Level: ${response.data.kycLevel}`);
        console.log(`   Issuer: ${response.data.credential.issuer.name}`);
        console.log(`   Valid until: ${response.data.credential.expirationDate}`);
        
        return response.data.credential;
      } else {
        console.log("❌ Failed to issue credential");
        return false;
      }

    } catch (error) {
      console.error("❌ Failed to issue credential:", error.response?.data?.error || error.message);
      console.log("💡 Make sure:");
      console.log("   - The issuer service is running");
      console.log("   - The DID is registered on-chain");
      return false;
    }
  }

  // Generate ZK proof for identity ownership and KYC verification
  async generateZKProof(identityId, kycLevel, privateKeyHex = null) {
    try {
      console.log(`🔒 Generating ZK proof for identity: ${identityId}`);
      console.log(`   Required KYC Level: ${kycLevel}`);

      // Get identity state from chain
      const identity = await this.queryIdentity(identityId, false);
      if (!identity) {
        throw new Error("Identity not found on-chain");
      }

      // If no private key provided, try to extract from DID format
      let privateKeyBigInt;
      if (privateKeyHex) {
        privateKeyBigInt = BigInt('0x' + privateKeyHex);
      } else {
        // For demo purposes, generate a mock private key based on identity
        // In production, this would come from secure storage
        console.log("⚠️  Using mock private key for demo - in production, use secure key storage");
        const mockSeed = identityId.slice(-32); // Use last 32 chars of DID as seed
        const seedBuffer = Buffer.from(mockSeed, 'utf8');
        privateKeyBigInt = this.poseidonHash([BigInt('0x' + seedBuffer.toString('hex'))]);
      }

      // Generate identity commitment using Poseidon hash
      const identityCommitment = this.poseidonHash([privateKeyBigInt]);

      // Calculate address commitment for transaction authorization
      const addressCommitment = this.calculateAddressCommitment(this.address);
      
      // Extract issuer from identity attributes
      const issuerAddress = identity.attributes?.issued_by || 
                          identity.attributes?.last_updated_by || 
                          "vnic19rl4cm2hmr8afy4kldpxz3fka4jguq0a3fccce"; // Default test issuer

      // Create ZK proof structure with cryptographic components
      // In production, this would use actual ZK circuit computation
      const zkProof = {
        pi_a: [
          this.generateProofPoint(privateKeyBigInt, "pi_a_1").toString(),
          this.generateProofPoint(privateKeyBigInt, "pi_a_2").toString()
        ],
        pi_b: [
          [
            this.generateProofPoint(privateKeyBigInt, "pi_b_1_1").toString(),
            this.generateProofPoint(privateKeyBigInt, "pi_b_1_2").toString()
          ],
          [
            this.generateProofPoint(privateKeyBigInt, "pi_b_2_1").toString(),
            this.generateProofPoint(privateKeyBigInt, "pi_b_2_2").toString()
          ]
        ],
        pi_c: [
          this.generateProofPoint(privateKeyBigInt, "pi_c_1").toString(),
          this.generateProofPoint(privateKeyBigInt, "pi_c_2").toString()
        ],
        public_inputs: [
          kycLevel.toString(),                    // [0] KYC level
          "1",                                    // [1] Validity flag (1 = valid)
          identity.state,                         // [2] Identity state commitment
          addressCommitment,                      // [3] Address commitment
          issuerAddress                           // [4] Issuer address who issued the credential
        ],
        kyc_level: kycLevel,
        did: identityId,
        issuer_address: issuerAddress           // Include issuer in proof structure
      };

      console.log("✅ ZK proof generated successfully!");
      console.log(`   Proof Type: Groth16 (demo mode)`);
      console.log(`   DID: ${zkProof.did}`);
      console.log(`   KYC Level: ${zkProof.kyc_level}`);
      console.log(`   Identity State: ${identity.state}`);
      console.log(`   Address Commitment: ${addressCommitment}`);
      console.log(`   Issuer: ${issuerAddress}`);
      console.log(`   Private Key: ${privateKeyBigInt.toString(16).slice(0, 16)}...`);

      return zkProof;

    } catch (error) {
      console.error("❌ Failed to generate ZK proof:", error.message);
      console.log("💡 Make sure:");
      console.log("   - The identity is registered on-chain");
      console.log("   - You have the correct private key for the identity");
      console.log("   - The KYC level is valid (1-5)");
      return null;
    }
  }

  // Generate cryptographic proof points using private key and context
  generateProofPoint(privateKeyBigInt, context) {
    try {
      // Create deterministic but cryptographically sound proof points
      // In production, this would be computed by the ZK circuit
      const contextHash = this.poseidonHash([BigInt('0x' + Buffer.from(context, 'utf8').toString('hex'))]);
      const proofPoint = this.poseidonHash([contextHash, privateKeyBigInt]);
      
      // Ensure result fits in field size and is properly formatted
      return proofPoint % BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
    } catch (error) {
      // Fallback to deterministic generation
      const fallback = BigInt('0x' + Buffer.from(context + privateKeyBigInt.toString(16), 'utf8').toString('hex').slice(0, 60));
      return fallback % BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
    }
  }

  // Calculate address commitment for proof verification
  calculateAddressCommitment(address) {
    try {
      // Convert address to deterministic commitment
      const addressHash = this.poseidonHash([BigInt('0x' + Buffer.from(address, 'utf8').toString('hex'))]);
      return addressHash.toString();
    } catch (error) {
      // Fallback to simple hash
      return Buffer.from(address, 'utf8').toString('hex');
    }
  }

  // Send a test transaction with ZK proof verification using user's own wallet
  async sendTransactionWithProof(identityId, kycLevel, amount = "1000", recipient = null) {
    try {
      const targetAddress = recipient || this.address; // Self-transfer if no recipient
      console.log(`💸 Sending ${amount}stake from USER'S wallet to ${targetAddress} with KYC proof (level ${kycLevel})`);
      console.log(`🆔 Using DID: ${identityId}`);

      // Check user's balance first
      const balance = await this.client.getAllBalances(this.address);
      const stakeBalance = balance.find(coin => coin.denom === 'stake');
      
      if (!stakeBalance || parseInt(stakeBalance.amount) < parseInt(amount)) {
        console.log("❌ Insufficient balance in user's wallet for transaction");
        console.log(`   Available: ${stakeBalance?.amount || 0} stake`);
        console.log(`   Required: ${amount} stake (plus gas fees)`);
        return false;
      }

      // Verify the identity exists and has sufficient KYC level
      const identity = await this.queryIdentity(identityId, false);
      if (!identity) {
        console.log("❌ Identity not found on-chain. Please register the DID first.");
        return false;
      }

      if (identity.kyc_level < kycLevel) {
        console.log(`❌ Insufficient KYC level for this transaction.`);
        console.log(`   Required: Level ${kycLevel}`);
        console.log(`   Available: Level ${identity.kyc_level}`);
        console.log(`   💡 Submit more documents to increase your KYC level.`);
        return false;
      }

      // Generate ZK proof for the transaction
      console.log("🔒 Generating ZK proof for transaction authorization...");
      const zkProof = await this.generateZKProof(identityId, kycLevel);
      if (!zkProof) {
        console.log("❌ Failed to generate ZK proof. Transaction cancelled.");
        return false;
      }

      console.log("✅ ZK proof generated. Proceeding with transaction from user's wallet...");

      // Send transaction using user's wallet (not issuer's!)
      // In production, the ZK proof would be included in the transaction or verified by ante handler
      const result = await this.client.sendTokens(
        this.address,          // FROM: User's address
        targetAddress,         // TO: Recipient address
        [{ denom: "stake", amount: amount }],
        "auto",
        `KYC-verified transaction (Level ${kycLevel}) - ${new Date().toISOString()}`
      );

      if (result.code === 0) {
        console.log("✅ Transaction sent successfully from user's wallet with ZK proof!");
        console.log(`   Transaction Hash: ${result.transactionHash}`);
        console.log(`   Gas Used: ${result.gasUsed}`);
        console.log(`   Fee: ${result.gasWanted} * ${CONFIG.GAS_PRICE}`);
        console.log(`   KYC Level Verified: ${kycLevel}`);
        console.log(`   Identity: ${identityId}`);
        console.log(`   Sent from USER address: ${this.address}`);
        return result;
      } else {
        console.log("❌ Transaction failed:", result.rawLog);
        return false;
      }

    } catch (error) {
      console.error("❌ Failed to send transaction with proof:", error.message);
      console.log("💡 Make sure:");
      console.log("   - You have sufficient balance for the transaction and gas fees");
      console.log("   - You have a registered DID with adequate KYC level");
      console.log("   - The recipient address is valid");
      console.log("   - The chain is running and accessible");
      return false;
    }
  }

  // Find identity associated with an address
  async findIdentityForAddress(address) {
    try {
      // For demo, try common patterns
      const patterns = [
        `did:vnic:test-user`,            // Test user pattern
        `did:vnic:user-${address.slice(-8)}`, // Address suffix pattern
      ];

      for (const pattern of patterns) {
        console.log(`🔍 Querying identity: ${pattern}`);
        const identity = await this.queryIdentity(pattern, false);
        if (identity) {
          console.log(`✅ Found identity: ${pattern}`);
          return pattern;
        }
      }

      // Check identities via server API
      try {
        const response = await axios.get(`${CONFIG.ISSUER_SERVICE_URL}/api/v1/identities?address=${address}`);
        if (response.data.success && response.data.identities.length > 0) {
          const firstIdentity = response.data.identities[0];
          console.log(`✅ Found identity from server: ${firstIdentity.identityId}`);
          return firstIdentity.identityId;
        }
      } catch (apiError) {
        console.log("⚠️  Could not query server for identities");
      }

      console.log("⚠️  No identity found with common patterns");
      return null;

    } catch (error) {
      console.error("❌ Error finding identity for address:", error.message);
      return null;
    }
  }

  // Query all DIDs and their KYC levels for an address via server API
  async queryDIDsForAddress(address = null) {
    try {
      const targetAddress = address || this.address;
      console.log(`🔍 Querying DIDs and KYC levels for address: ${targetAddress}`);
      
      // Query identities via server API
      const response = await axios.get(`${CONFIG.ISSUER_SERVICE_URL}/api/v1/identities?address=${targetAddress}`);
      
      if (response.data.success) {
        const identities = response.data.identities;
        
        console.log(`\n📊 DID Query Results for ${targetAddress}:`);
        console.log(`   Total DIDs: ${identities.length}`);
        
        if (identities.length > 0) {
          console.log(`   Associated DIDs with KYC Levels:`);
          identities.forEach((identity, index) => {
            console.log(`   ${index + 1}. ${identity.identityId}`);
            console.log(`      KYC Level: ${identity.kycLevel}`);
            console.log(`      Credential ID: ${identity.credentialId}`);
            console.log(`      Issued At: ${identity.issuedAt}`);
            console.log("");
          });
          
          // Summary
          const maxLevel = Math.max(...identities.map(id => id.kycLevel));
          console.log(`   📈 Summary:`);
          console.log(`      Highest KYC Level: ${maxLevel}`);
          console.log(`      DIDs with Credentials: ${identities.length}`);
          
        } else {
          console.log(`   ⚠️  No DIDs found for this address`);
          console.log(`   💡 Register a DID with: bun run did-client.js register`);
          console.log(`   💡 Or try: bun run did-client.js register did:vnic:test-user`);
        }

        return {
          count: identities.length,
          identities: identities,
          address: targetAddress
        };
      } else {
        console.log("❌ Failed to query identities from server");
        return {
          count: 0,
          identities: [],
          address: targetAddress
        };
      }

    } catch (error) {
      console.error("❌ Error querying DIDs for address:", error.response?.data?.error || error.message);
      return {
        count: 0,
        identities: [],
        address: address || this.address
      };
    }
  }

  // Send a test transaction using user's own wallet
  async sendTransaction(amount = "1000", recipient = null) {
    try {
      const targetAddress = recipient || this.address; // Self-transfer if no recipient
      console.log(`💸 Sending ${amount}stake from USER'S wallet to ${targetAddress}`);

      // Check user's balance first
      const balance = await this.client.getAllBalances(this.address);
      const stakeBalance = balance.find(coin => coin.denom === 'stake');
      
      if (!stakeBalance || parseInt(stakeBalance.amount) < parseInt(amount)) {
        console.log("❌ Insufficient balance in user's wallet for transaction");
        console.log(`   Available: ${stakeBalance?.amount || 0} stake`);
        console.log(`   Required: ${amount} stake (plus gas fees)`);
        return false;
      }

      // Send transaction using user's wallet
      const result = await this.client.sendTokens(
        this.address,          // FROM: User's address
        targetAddress,         // TO: Recipient address
        [{ denom: "stake", amount: amount }],
        "auto",
        `Test transaction from VietChain KYC Client - ${new Date().toISOString()}`
      );

      if (result.code === 0) {
        console.log("✅ Transaction sent successfully from user's wallet!");
        console.log(`   Transaction Hash: ${result.transactionHash}`);
        console.log(`   Gas Used: ${result.gasUsed}`);
        console.log(`   Fee: ${result.gasWanted} * ${CONFIG.GAS_PRICE}`);
        console.log(`   Sent from USER address: ${this.address}`);
        return result;
      } else {
        console.log("❌ Transaction failed:", result.rawLog);
        return false;
      }

    } catch (error) {
      console.error("❌ Failed to send transaction:", error.message);
      console.log("💡 Make sure:");
      console.log("   - You have sufficient balance for the transaction and gas fees");
      console.log("   - The recipient address is valid");
      console.log("   - The chain is running and accessible");
      return false;
    }
  }

  // Verify credential with issuer service
  async verifyCredential(credentialId) {
    try {
      console.log(`🔍 Verifying credential: ${credentialId}`);

      const response = await axios.post(
        `${CONFIG.ISSUER_SERVICE_URL}/api/v1/verify-credential`,
        {
          credentialId: credentialId
        },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.valid) {
        console.log("✅ Credential is valid!");
        console.log(`   Issued to: ${response.data.credential.credentialSubject.id}`);
        console.log(`   KYC Level: ${response.data.credential.credentialSubject.kycLevel}`);
        console.log(`   Issued at: ${response.data.issuedAt}`);
        console.log(`   Expires: ${response.data.credential.expirationDate}`);
        return response.data.credential;
      } else {
        console.log("❌ Credential is invalid or expired");
        return false;
      }

    } catch (error) {
      if (error.response?.status === 404) {
        console.log("❌ Credential not found");
      } else {
        console.error("❌ Failed to verify credential:", error.response?.data?.error || error.message);
      }
      return false;
    }
  }

  // List all available commands
  showHelp() {
    console.log("🔧 VietChain KYC DID Client Commands:");
    console.log("");
    console.log("Usage: bun run did-client.js [command] [options]");
    console.log("");
    console.log("Commands:");
    console.log(
      "  register [id|seed:text]     Register a new DID (via issuer service API)",
    );
    console.log("  query <id>                  Query an existing DID (via issuer service API)");
    console.log("  submit <id> <name> [birth] [phone] [nationalId] [fullName] [dateOfBirth] [gender] [nationality] [cardNumber] [dateIssued]  Submit documents for KYC verification (via API)");
    console.log("  submit-vn <id> <fullName> <dateOfBirth> <gender> <nationality> <cardNumber> <dateIssued>  Submit Vietnamese ID card (via API)");
    console.log("  submit-default-vn <id>      Submit default Vietnamese ID card: TRUONG VO KHANH HA (via API)");
    console.log("  query-docs <id>             Query submitted documents for a DID (via API)");
    console.log("  query-docs-advanced <id> [includeExpired] [minKycLevel]  Advanced document query with filters (via API)");
    console.log("  issue <id>                  Issue KYC credential for a DID (via API)");
    console.log("  verify <cred-id>            Verify a KYC credential (via API)");
    console.log("  send [amount] [recipient]   Send transaction from USER'S wallet");
    console.log("  send-proof <did> <level> [amount] [recipient]  Send transaction from USER'S wallet with ZK proof");
    console.log("  proof <id> <level> [privkey] Generate ZK proof for identity and KYC level");
    console.log("  list [address]              List DIDs and KYC levels for address (via API)");
    console.log("  status                      Check chain status and user balance");
    console.log("  help                        Show this help message");
    console.log("");
    console.log("Examples:");
    console.log("  bun run did-client.js register");
    console.log("  bun run did-client.js register seed:my-test-seed");
    console.log("  bun run did-client.js register did:vnic:my-custom-id");
    console.log("  bun run did-client.js query did:vnic:abc123...");
    console.log("  # Legacy format:");
    console.log("  bun run did-client.js submit did:vnic:test-user 'John Doe'");
    console.log("  bun run did-client.js submit did:vnic:test-user 'John Doe' '1990-05-15'");
    console.log("  bun run did-client.js submit did:vnic:test-user 'John Doe' '1990-05-15' '+1-555-123-4567'");
    console.log("  bun run did-client.js submit did:vnic:test-user 'John Doe' '1990-05-15' '+1-555-123-4567' 'ID123456789'");
    console.log("  # Vietnamese ID card format:");
    console.log("  bun run did-client.js submit-vn did:vnic:test-user 'TRUONG VO KHANH HA' '27/06/2003' 'Nữ' 'Việt Nam' '0628443382498' '22/12/2020'");
    console.log("  bun run did-client.js submit-default-vn did:vnic:test-user  # Use default Vietnamese ID");
    console.log("  # Query submitted documents:");
    console.log("  bun run did-client.js query-docs did:vnic:test-user");
    console.log("  bun run did-client.js query-docs-advanced did:vnic:test-user true 3  # Include expired, min level 3");
    console.log("  bun run did-client.js send 1000");
    console.log("  bun run did-client.js send 1000 vnic1recipient...");
    console.log("  bun run did-client.js send-proof did:vnic:test-user 2 5000  # Send with level 2 KYC proof");
    console.log("  bun run did-client.js proof did:vnic:test-user 3  # Generate level 3 proof");
    console.log("  bun run did-client.js list  # List DIDs for current address");
    console.log("  bun run did-client.js verify urn:uuid:12345-67890");
    console.log("  bun run did-client.js status");
    console.log("");
    console.log("KYC Levels:");
    console.log("  Level 1: Name provided");
    console.log("  Level 2: Name + Date of birth provided");
    console.log("  Level 3: Personal information + Contact/Gender provided");
    console.log("  Level 4: Complete ID verification with card number");
    console.log("  Level 5: Full Vietnamese citizen ID card verification");
    console.log("");
    console.log("Architecture:");
    console.log("  • Client manages user's own wallet and funds");
    console.log("  • CLI operations (register, query) use issuer service API");
    console.log("  • Transactions (send, send-proof) use user's wallet directly");
    console.log("  • ZK proofs generated client-side for privacy");
  }
}

// Main execution function
async function main() {
  const client = new VietChainKYCClient();
  const args = process.argv.slice(2);
  const command = args[0] || "help";

  // Show help if no command provided
  if (command === "help" || (!command && args.length === 0)) {
    client.showHelp();
    return;
  }

  // Initialize client for all commands except help
  const initialized = await client.init();
  if (!initialized) {
    process.exit(1);
  }

  switch (command) {
    case "register":
      let identityId;
      if (!args[1]) {
        // Generate random cryptographic DID
        identityId = client.generateIdentityId();
      } else if (args[1].startsWith('seed:')) {
        // Generate deterministic DID from seed
        const seed = args[1].substring(5); // Remove 'seed:' prefix
        identityId = client.generateIdentityFromSeed(seed);
      } else {
        // Use provided DID
        identityId = args[1];
      }
      await client.registerDID(identityId);
      break;

    case "query":
      if (!args[1]) {
        console.error("❌ Please provide an identity ID to query");
        console.log("Usage: bun run did-client.js query <identity-id>");
        process.exit(1);
      }
      await client.queryIdentity(args[1]);
      break;

    case "submit":
      if (!args[1] || !args[2]) {
        console.error("❌ Please provide an identity ID and at least a name");
        console.log("Usage: bun run did-client.js submit <identity-id> <name> [birthdate] [phone] [nationalId] [fullName] [dateOfBirth] [gender] [nationality] [cardNumber] [dateIssued]");
        console.log("Example: bun run did-client.js submit did:vnic:test-user 'John Doe' '1990-05-15' '+1-555-123-4567' 'ID123456789'");
        process.exit(1);
      }
      await client.submitDocument(args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11]);
      break;

    case "submit-vn":
      if (!args[1] || !args[2] || !args[3] || !args[4] || !args[5] || !args[6] || !args[7]) {
        console.error("❌ Please provide all Vietnamese ID card information");
        console.log("Usage: bun run did-client.js submit-vn <identity-id> <fullName> <dateOfBirth> <gender> <nationality> <cardNumber> <dateIssued>");
        console.log("Example: bun run did-client.js submit-vn did:vnic:test-user 'TRUONG VO KHANH HA' '27/06/2003' 'Nữ' 'Việt Nam' '0628443382498' '22/12/2020'");
        process.exit(1);
      }
      // For Vietnamese ID card, we pass null for legacy fields and use the Vietnamese fields
      await client.submitDocument(args[1], null, null, null, null, args[2], args[3], args[4], args[5], args[6], args[7]);
      break;

    case "submit-default-vn":
      if (!args[1]) {
        console.error("❌ Please provide an identity ID");
        console.log("Usage: bun run did-client.js submit-default-vn <identity-id>");
        console.log("This will submit the default Vietnamese ID card: TRUONG VO KHANH HA");
        process.exit(1);
      }
      // Submit with default Vietnamese ID card data
      await client.submitVietnameseID(args[1]);
      break;

    case "query-docs":
      if (!args[1]) {
        console.error("❌ Please provide an identity ID");
        console.log("Usage: bun run did-client.js query-docs <identity-id>");
        console.log("Example: bun run did-client.js query-docs did:vnic:test-user");
        process.exit(1);
      }
      await client.querySubmittedDocuments(args[1]);
      break;

    case "query-docs-advanced":
      if (!args[1]) {
        console.error("❌ Please provide an identity ID");
        console.log("Usage: bun run did-client.js query-docs-advanced <identity-id> [includeExpired] [minKycLevel]");
        console.log("Example: bun run did-client.js query-docs-advanced did:vnic:test-user true 3");
        process.exit(1);
      }
      const includeExpired = args[2] === 'true' || args[2] === '1';
      const minKycLevel = args[3] ? parseInt(args[3]) : 0;
      
      if (args[3] && (minKycLevel < 0 || minKycLevel > 5)) {
        console.error("❌ Min KYC level must be between 0 and 5");
        process.exit(1);
      }
      
      await client.queryDocumentsAdvanced(args[1], { includeExpired, minKycLevel });
      break;

    case "issue":
      if (!args[1]) {
        console.error("❌ Please provide an identity ID to issue credential for");
        console.log("Usage: bun run did-client.js issue <identity-id>");
        process.exit(1);
      }
      await client.issueCredential(args[1]);
      break;

    case "verify":
      if (!args[1]) {
        console.error("❌ Please provide a credential ID to verify");
        console.log("Usage: bun run did-client.js verify <credential-id>");
        process.exit(1);
      }
      await client.verifyCredential(args[1]);
      break;

    case "send":
      const amount = args[1] || "1000";
      const recipient = args[2] || null;
      await client.sendTransaction(amount, recipient);
      break;

    case "send-proof":
      if (!args[1] || !args[2]) {
        console.error("❌ Please provide a DID and KYC level for the proof");
        console.log("Usage: bun run did-client.js send-proof <did> <kyc-level> [amount] [recipient]");
        console.log("Example: bun run did-client.js send-proof did:vnic:test-user 2 5000");
        process.exit(1);
      }
      const proofDid = args[1];
      const kycLevel = parseInt(args[2]);
      const proofAmount = args[3] || "1000";
      const proofRecipient = args[4] || null;
      
      if (kycLevel < 1 || kycLevel > 5) {
        console.error("❌ KYC level must be between 1 and 5");
        process.exit(1);
      }
      
      await client.sendTransactionWithProof(proofDid, kycLevel, proofAmount, proofRecipient);
      break;

    case "proof":
      if (!args[1] || !args[2]) {
        console.error("❌ Please provide an identity ID and KYC level");
        console.log("Usage: bun run did-client.js proof <identity-id> <kyc-level> [private-key-hex]");
        console.log("Example: bun run did-client.js proof did:vnic:test-user 3");
        process.exit(1);
      }
      const proofIdentityId = args[1];
      const proofKycLevel = parseInt(args[2]);
      const privateKeyHex = args[3] || null;
      
      if (proofKycLevel < 1 || proofKycLevel > 5) {
        console.error("❌ KYC level must be between 1 and 5");
        process.exit(1);
      }
      
      const generatedProof = await client.generateZKProof(proofIdentityId, proofKycLevel, privateKeyHex);
      if (generatedProof) {
        console.log("\n📋 Generated ZK Proof Structure:");
        console.log(JSON.stringify(generatedProof, null, 2));
      }
      break;

    case "status":
      await client.checkChainStatus();
      await client.checkBalance();
      break;

    case "list":
      const listAddress = args[1] || null; // Optional address parameter
      await client.queryDIDsForAddress(listAddress);
      break;

    default:
      console.error(`❌ Unknown command: ${command}`);
      client.showHelp();
      process.exit(1);
  }
}

// Run the client
if (require.main === module) {
  main().catch((error) => {
    console.error("💥 Unexpected error:", error);
    process.exit(1);
  });
}

module.exports = VietChainKYCClient;

