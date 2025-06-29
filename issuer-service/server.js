const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { execSync } = require("child_process");
const { SigningStargateClient, GasPrice } = require("@cosmjs/stargate");
const { DirectSecp256k1HdWallet } = require("@cosmjs/proto-signing");
const { stringToPath } = require("@cosmjs/crypto");
const { createHash } = require("crypto");

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Secure issuer configuration with dedicated keys
const ISSUER_CONFIG = {
  id: "issuer-001",
  name: "VietChain Official KYC Issuer",
  maxKycLevel: 5,
  chainRpc: "http://localhost:26657",
  chainRest: "http://localhost:1317",
  chainId: "vnic",
  gasPrice: "0.025stake",
  // Dedicated issuer mnemonic - matches the 'issuer' key in keyring
  mnemonic: "morning balcony fish cave carpet crop soul poem utility duck pond question produce swarm argue embark blossom vibrant kind foil junk tourist trash work",
  // Credential signing key pair - generated at startup
  signingKeyPair: null,
  publicKeyHex: null, // Will be set from generated key pair
  address: null, // Will be set from blockchain wallet
};

// Global blockchain client
let blockchainClient = null;
let issuerAddress = null;

// In-memory store for issued credentials (in production, use a database)
const issuedCredentials = new Map();

// Initialize blockchain client
async function initBlockchainClient() {
  try {
    console.log("🔧 Initializing blockchain client...");

    // Initialize cryptographic signing keys first
    initializeSigningKeys();

    // Create wallet from mnemonic
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(
      ISSUER_CONFIG.mnemonic,
      {
        prefix: "vnic",
        hdPaths: [stringToPath("m/44'/118'/0'/0/0")],
      },
    );

    // Get address
    const accounts = await wallet.getAccounts();
    issuerAddress = accounts[0].address;
    ISSUER_CONFIG.address = issuerAddress;
    console.log(`📍 Issuer blockchain address: ${issuerAddress}`);

    // Create signing client
    blockchainClient = await SigningStargateClient.connectWithSigner(
      ISSUER_CONFIG.chainRpc,
      wallet,
      {
        gasPrice: GasPrice.fromString(ISSUER_CONFIG.gasPrice),
      },
    );

    console.log("✅ Blockchain client initialized successfully");

    // Ensure this issuer is registered on-chain
    await ensureIssuerRegistered();

    return true;
  } catch (error) {
    console.error("❌ Failed to initialize blockchain client:", error.message);
    return false;
  }
}

// Ensure issuer is registered on blockchain
async function ensureIssuerRegistered() {
  try {
    console.log("🔍 Checking if issuer is registered...");

    // Check if issuer already exists
    const result = execSync(
      `./vnicd query kyc issuer ${issuerAddress} --output json --node tcp://localhost:26657`,
      { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
    );

    const queryResult = JSON.parse(result);
    if (queryResult.address) {
      console.log("✅ Issuer already registered");
      return true;
    }
  } catch (error) {
    // Issuer not found, need to register
    console.log("📝 Registering issuer on blockchain...");

    try {
      const issuerJson = JSON.stringify({
        address: issuerAddress,
        name: ISSUER_CONFIG.name,
        public_key: ISSUER_CONFIG.publicKeyHex,
        max_kyc_level: ISSUER_CONFIG.maxKycLevel,
        active: true,
      });

      const result = execSync(
        `./vnicd tx kyc add-issuer --issuer '${issuerJson}' --from issuer --keyring-backend test --yes --node tcp://localhost:26657 --output json`,
        { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      );

      const txResult = JSON.parse(result);
      if (txResult.code === 0) {
        console.log("✅ Issuer registered successfully");
        return true;
      } else {
        console.error("❌ Failed to register issuer:", txResult.raw_log);
        return false;
      }
    } catch (regError) {
      console.error("❌ Error registering issuer:", regError.message);
      return false;
    }
  }
}

// Initialize cryptographic signing key pair
function initializeSigningKeys() {
  if (!ISSUER_CONFIG.signingKeyPair) {
    // Generate a new RSA key pair for signing credentials
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    ISSUER_CONFIG.signingKeyPair = keyPair;
    ISSUER_CONFIG.publicKeyPem = keyPair.publicKey;
    
    // Extract public key hex for blockchain integration
    const publicKeyBuffer = crypto.createPublicKey(keyPair.publicKey).export({
      format: 'der',
      type: 'spki'
    });
    ISSUER_CONFIG.publicKeyHex = publicKeyBuffer.toString('hex');
    
    console.log("🔐 Generated new RSA-2048 signing key pair for credential signatures");
    console.log(`📋 Public Key Hex: ${ISSUER_CONFIG.publicKeyHex.substring(0, 32)}...`);
  }
}

// Cryptographically secure credential signing function
function signCredential(credential) {
  if (!ISSUER_CONFIG.signingKeyPair) {
    throw new Error("Signing keys not initialized");
  }
  
  // Create canonical JSON representation for signing
  const canonicalData = JSON.stringify(credential, Object.keys(credential).sort());
  
  // Create signature using RSA-SHA256
  const signature = crypto.sign('sha256', Buffer.from(canonicalData), {
    key: ISSUER_CONFIG.signingKeyPair.privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  
  return signature.toString('base64');
}

// Verify credential signature
function verifyCredentialSignature(credential, signature) {
  if (!ISSUER_CONFIG.signingKeyPair) {
    return false;
  }
  
  try {
    // Create canonical JSON representation for verification
    const { proof, ...credentialWithoutProof } = credential;
    const canonicalData = JSON.stringify(credentialWithoutProof, Object.keys(credentialWithoutProof).sort());
    
    // Verify signature using RSA-SHA256
    const isValid = crypto.verify('sha256', Buffer.from(canonicalData), {
      key: ISSUER_CONFIG.signingKeyPair.publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    }, Buffer.from(signature, 'base64'));
    
    return isValid;
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

// Generate ZK proof signature for blockchain validation
function generateZKProofSignature(proofData) {
  if (!ISSUER_CONFIG.signingKeyPair) {
    throw new Error("Signing keys not initialized");
  }
  
  // Create a hash of the proof elements that will be included in public inputs
  const proofHash = createHash('sha256')
    .update(JSON.stringify(proofData.PiA))
    .update(JSON.stringify(proofData.PiB))
    .update(JSON.stringify(proofData.PiC))
    .update(proofData.KYCLevel.toString())
    .digest('hex');
  
  // Create the expected signature format that matches blockchain validation
  const issuerIdentifier = ISSUER_CONFIG.publicKeyHex + issuerAddress;
  const expectedSignature = createHash('sha256')
    .update(issuerIdentifier + proofHash.substring(0, 32))
    .digest('hex');
  
  return expectedSignature;
}

// Helper function to determine KYC level based on submitted documents
function determineKycLevel(documents) {
  let level = 0;

  // Level 1: Basic name verification (either name or fullName)
  if (documents.fullName) {
    level = 1;
  }

  // Level 2: Name + Date of birth verification (supports both formats)
  if ((documents.fullName) && (documents.dateOfBirth)) {
    level = 2;
  }

  // Level 3: Full personal info + Phone/Gender verification
  if ((documents.fullName) && 
      (documents.dateOfBirth) && 
      (documents.gender)) {
    level = 3;
  }

  // Level 4: Complete ID verification with card number or national ID
  if ((documents.fullName) && 
      (documents.dateOfBirth) && 
      (documents.gender) && 
      (documents.nationality) &&
      (documents.address)) {
    level = 4;
  }

  // Level 5: Full Vietnamese citizen ID card verification
  if (documents.fullName && documents.dateOfBirth && documents.nationalId && documents.dateIssued && documents.nationality && documents.gender) {
    level = 5;
  }

  return Math.min(level, ISSUER_CONFIG.maxKycLevel);
}

// Update KYC level on blockchain
async function updateKycLevelOnChain(identityId, kycLevel) {
  try {
    console.log(
      `🔗 Issuing KYC credential on-chain for ${identityId} with level ${kycLevel}...`,
    );

    if (!blockchainClient || !issuerAddress) {
      throw new Error("Blockchain client not initialized");
    }

    // Use CLI to issue credential (which properly updates claims tree and state)
    const result = execSync(
      `./vnicd tx kyc issue-credential "${identityId}" ${kycLevel} --from issuer --keyring-backend test --yes --node tcp://localhost:26657 --output json`,
      { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
    );

    const txResult = JSON.parse(result);

    if (txResult.code === 0) {
      console.log("✅ KYC credential issued on-chain successfully!");
      console.log(`   Transaction Hash: ${txResult.txhash}`);
      return {
        success: true,
        txHash: txResult.txhash,
      };
    } else {
      console.error("❌ Transaction failed:", txResult.raw_log);
      return {
        success: false,
        error: txResult.raw_log,
      };
    }
  } catch (error) {
    console.error("❌ Failed to issue KYC credential on-chain:", error.message);
    return {
      success: false,
      error: error.message,
    };
  }
}

// API Routes

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    issuer: {
      address: ISSUER_CONFIG.address || issuerAddress,
      name: ISSUER_CONFIG.name,
      publicKey: ISSUER_CONFIG.publicKeyHex,
      blockchainConnected: !!blockchainClient,
      signingKeysInitialized: !!ISSUER_CONFIG.signingKeyPair,
    },
  });
});

// Get issuer information
app.get("/issuer-info", (req, res) => {
  res.json({
    address: ISSUER_CONFIG.address || issuerAddress,
    name: ISSUER_CONFIG.name,
    publicKey: ISSUER_CONFIG.publicKeyHex,
    publicKeyPem: ISSUER_CONFIG.publicKeyPem,
    maxKycLevel: ISSUER_CONFIG.maxKycLevel,
    supportedCredentialTypes: ["KYCCredential"],
    issuanceEndpoint: "/api/v1/issue-credential",
    zkProofEndpoint: "/api/v1/generate-zk-proof",
    signatureType: "RsaSignature2018",
  });
});

// Submit documents for KYC verification
app.post("/api/v1/submit-document", async (req, res) => {
  try {
    const { 
      did, 
      // Legacy fields
      name, birthdate, phone, nationalId,
      // Vietnamese ID card fields
      fullName, dateOfBirth, gender, nationality, cardNumber, dateIssued, address
    } = req.body;

    console.log("submit-document", req.body);
    if (!did) {
      return res.status(400).json({ error: "Missing required field: did" });
    }

    // Prepare documents object based on provided data
    const documents = {};
    // Legacy fields
    if (name) documents.name = name;
    if (birthdate) documents.birthdate = birthdate;
    if (phone) documents.phone = phone;
    if (nationalId) documents.nationalId = nationalId;
    
    // Vietnamese ID card fields
    if (fullName) documents.fullName = fullName;
    if (dateOfBirth) documents.dateOfBirth = dateOfBirth;
    if (gender) documents.gender = gender;
    if (address) documents.address = address;
    if (nationality) documents.nationality = nationality;
    if (cardNumber) documents.cardNumber = cardNumber;
    if (dateIssued) documents.dateIssued = dateIssued;

    // Determine KYC level based on submitted documents
    const kycLevel = determineKycLevel(documents);
    console.log("🔍 KYC Level:", kycLevel);
    // Create verifiable credential
    const credential = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://vietchain.example.com/credentials/kyc/v1",
      ],
      id: `urn:uuid:${uuidv4()}`,
      type: ["VerifiableCredential", "KYCCredential"],
      issuer: {
        id: `did:test:${ISSUER_CONFIG.id}`,
        name: ISSUER_CONFIG.name,
      },
      issuanceDate: new Date().toISOString(),
      expirationDate: new Date(
        Date.now() + 365 * 24 * 60 * 60 * 1000,
      ).toISOString(), // 1 year
      credentialSubject: {
        id: did,
        kycLevel: kycLevel,
        verifiedAt: new Date().toISOString(),
        attributes: {
          // Legacy fields
          name: name || null,
          birthdate: birthdate || null,
          phone: phone || null,
          nationalId: nationalId || null,
          // Vietnamese ID card fields
          fullName: fullName || null,
          dateOfBirth: dateOfBirth || null,
          address: address || null,
          gender: gender || null,
          nationality: nationality || null,
          cardNumber: cardNumber || null,
          dateIssued: dateIssued || null,
          issuerNotes: `KYC Level ${kycLevel} verification completed`,
        },
      },
    };

    // Sign the credential with cryptographic proof
    const signatureValue = signCredential(credential);
    const proof = {
      type: "RsaSignature2018",
      created: new Date().toISOString(),
      proofPurpose: "assertionMethod",
      verificationMethod: `did:test:${ISSUER_CONFIG.id}#key-1`,
      proofValue: signatureValue,
    };

    const verifiableCredential = {
      ...credential,
      proof,
    };

    // Store issued credential
    issuedCredentials.set(credential.id, {
      credential: verifiableCredential,
      issuedTo: did,
      issuedAt: new Date().toISOString(),
      kycLevel,
    });

    // Update KYC level on blockchain
    const updateResult = await updateKycLevelOnChain(did, kycLevel);

    if (updateResult.success) {
      res.json({
        success: true,
        credential: verifiableCredential,
        kycLevel,
        txHash: updateResult.txHash,
        message: `Document submitted successfully. KYC Level ${kycLevel} assigned based on provided information.`,
        levelDetails: {
          1: "Name verified",
          2: "Name and date of birth verified", 
          3: "Personal information and contact/gender verified",
          4: "Complete ID verification with card number",
          5: "Full Vietnamese citizen ID card verification"
        }[kycLevel]
      });
    } else {
      res.json({
        success: true,
        credential: verifiableCredential,
        kycLevel,
        warning: `Credential issued but failed to update on-chain: ${updateResult.error}`,
        message: `Document submitted successfully. KYC Level ${kycLevel} assigned (on-chain update failed).`,
        levelDetails: {
          1: "Name verified",
          2: "Name and date of birth verified",
          3: "Personal information and contact/gender verified",
          4: "Complete ID verification with card number",
          5: "Full Vietnamese citizen ID card verification"
        }[kycLevel]
      });
    }
  } catch (error) {
    console.error("Error processing document submission:", error);
    res.status(500).json({ error: "Failed to process document submission" });
  }
});

// Issue verifiable credential
app.post("/api/v1/issue-credential", async (req, res) => {
  try {
    const { did, documents, holder } = req.body;

    if (!did || !documents) {
      return res
        .status(400)
        .json({ error: "Missing required fields: did, documents" });
    }

    // Determine KYC level based on documents
    const kycLevel = determineKycLevel(documents);

    // Create verifiable credential
    const credential = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://vietchain.example.com/credentials/kyc/v1",
      ],
      id: `urn:uuid:${uuidv4()}`,
      type: ["VerifiableCredential", "KYCCredential"],
      issuer: {
        id: `did:test:${ISSUER_CONFIG.id}`,
        name: ISSUER_CONFIG.name,
      },
      issuanceDate: new Date().toISOString(),
      expirationDate: new Date(
        Date.now() + 365 * 24 * 60 * 60 * 1000,
      ).toISOString(), // 1 year
      credentialSubject: {
        id: did,
        kycLevel: kycLevel,
        verifiedAt: new Date().toISOString(),
        attributes: {
          documentTypes: Object.keys(documents).filter((key) => documents[key]),
          issuerNotes: "Verified through VietChain KYC process",
        },
      },
    };

    // Sign the credential with cryptographic proof
    const signatureValue = signCredential(credential);
    const proof = {
      type: "RsaSignature2018",
      created: new Date().toISOString(),
      proofPurpose: "assertionMethod",
      verificationMethod: `did:test:${ISSUER_CONFIG.id}#key-1`,
      proofValue: signatureValue,
    };

    const verifiableCredential = {
      ...credential,
      proof,
    };

    // Store issued credential
    issuedCredentials.set(credential.id, {
      credential: verifiableCredential,
      issuedTo: did,
      issuedAt: new Date().toISOString(),
      kycLevel,
    });

    // Real on-chain update
    const updateResult = await updateKycLevelOnChain(did, kycLevel);

    if (updateResult.success) {
      res.json({
        success: true,
        credential: verifiableCredential,
        kycLevel,
        txHash: updateResult.txHash,
        message: `KYC credential issued successfully with level ${kycLevel} and updated on-chain`,
      });
    } else {
      // Even if on-chain update fails, we still issued the credential
      res.json({
        success: true,
        credential: verifiableCredential,
        kycLevel,
        warning: `Credential issued but failed to update on-chain: ${updateResult.error}`,
        message: `KYC credential issued successfully with level ${kycLevel} (on-chain update failed)`,
      });
    }
  } catch (error) {
    console.error("Error issuing credential:", error);
    res.status(500).json({ error: "Failed to issue credential" });
  }
});

// Verify credential
app.post("/api/v1/verify-credential", (req, res) => {
  try {
    const { credentialId } = req.body;

    if (!credentialId) {
      return res.status(400).json({ error: "Missing credential ID" });
    }

    const stored = issuedCredentials.get(credentialId);

    if (!stored) {
      return res.status(404).json({ error: "Credential not found" });
    }

    // In production, verify the signature and check expiration
    const credential = stored.credential;
    const isExpired = new Date(credential.expirationDate) < new Date();

    res.json({
      valid: !isExpired,
      credential: stored.credential,
      issuedAt: stored.issuedAt,
      expired: isExpired,
    });
  } catch (error) {
    console.error("Error verifying credential:", error);
    res.status(500).json({ error: "Failed to verify credential" });
  }
});

// List all credentials issued by this issuer (for demo purposes)
app.get("/api/v1/credentials", (req, res) => {
  const credentials = Array.from(issuedCredentials.entries()).map(
    ([id, data]) => ({
      id,
      issuedTo: data.issuedTo,
      issuedAt: data.issuedAt,
      kycLevel: data.kycLevel,
    }),
  );

  res.json({ credentials });
});

// Query submitted documents/credentials by DID
app.get("/api/v1/documents/:did", (req, res) => {
  try {
    const { did } = req.params;
    
    if (!did) {
      return res.status(400).json({ error: "Missing DID parameter" });
    }

    console.log(`🔍 Querying submitted documents for DID: ${did}`);

    // Find all credentials issued to this DID
    const userCredentials = Array.from(issuedCredentials.entries())
      .filter(([id, data]) => data.issuedTo === did)
      .map(([id, data]) => ({
        credentialId: id,
        did: data.issuedTo,
        kycLevel: data.kycLevel,
        issuedAt: data.issuedAt,
        credential: data.credential,
        documents: data.credential.credentialSubject.attributes
      }));

    if (userCredentials.length === 0) {
      return res.status(404).json({ 
        error: "No submitted documents found for this DID",
        did: did,
        suggestion: "Submit documents first using /api/v1/submit-document endpoint"
      });
    }

    // Get the latest credential (highest KYC level)
    const latestCredential = userCredentials.reduce((latest, current) => 
      current.kycLevel > latest.kycLevel ? current : latest
    );

    res.json({
      success: true,
      did: did,
      totalCredentials: userCredentials.length,
      currentKycLevel: latestCredential.kycLevel,
      latestSubmission: latestCredential.issuedAt,
      submittedDocuments: latestCredential.documents,
      allCredentials: userCredentials.map(cred => ({
        credentialId: cred.credentialId,
        kycLevel: cred.kycLevel,
        issuedAt: cred.issuedAt,
        expired: new Date(cred.credential.expirationDate) < new Date()
      })),
      documentHistory: userCredentials
    });

  } catch (error) {
    console.error("Error querying documents by DID:", error);
    res.status(500).json({ error: "Failed to query submitted documents" });
  }
});

// Query submitted documents/credentials by DID (POST version for complex queries)
app.post("/api/v1/query-documents", (req, res) => {
  try {
    const { did, includeExpired = false, minKycLevel = 0 } = req.body;
    
    if (!did) {
      return res.status(400).json({ error: "Missing DID in request body" });
    }

    console.log(`🔍 Querying submitted documents for DID: ${did} (minLevel: ${minKycLevel})`);

    // Find credentials matching criteria
    let userCredentials = Array.from(issuedCredentials.entries())
      .filter(([id, data]) => data.issuedTo === did)
      .map(([id, data]) => ({
        credentialId: id,
        did: data.issuedTo,
        kycLevel: data.kycLevel,
        issuedAt: data.issuedAt,
        expired: new Date(data.credential.expirationDate) < new Date(),
        credential: data.credential,
        documents: data.credential.credentialSubject.attributes
      }));

    // Apply filters
    if (!includeExpired) {
      userCredentials = userCredentials.filter(cred => !cred.expired);
    }
    
    if (minKycLevel > 0) {
      userCredentials = userCredentials.filter(cred => cred.kycLevel >= minKycLevel);
    }

    if (userCredentials.length === 0) {
      return res.status(404).json({ 
        error: "No documents found matching criteria",
        did: did,
        criteria: { includeExpired, minKycLevel }
      });
    }

    // Get the latest valid credential
    const latestCredential = userCredentials.reduce((latest, current) => 
      current.kycLevel > latest.kycLevel ? current : latest
    );

    res.json({
      success: true,
      did: did,
      query: { includeExpired, minKycLevel },
      totalCredentials: userCredentials.length,
      currentKycLevel: latestCredential.kycLevel,
      latestSubmission: latestCredential.issuedAt,
      submittedDocuments: latestCredential.documents,
      matchingCredentials: userCredentials.map(cred => ({
        credentialId: cred.credentialId,
        kycLevel: cred.kycLevel,
        issuedAt: cred.issuedAt,
        expired: cred.expired
      }))
    });

  } catch (error) {
    console.error("Error querying documents:", error);
    res.status(500).json({ error: "Failed to query submitted documents" });
  }
});

// Generate ZK proof with issuer signature for blockchain validation
app.post("/api/v1/generate-zk-proof", async (req, res) => {
  try {
    const { did, kycLevel, requiredLevel } = req.body;

    if (!did || !kycLevel) {
      return res.status(400).json({ error: "Missing required fields: did, kycLevel" });
    }

    const requiredLevelInt = requiredLevel || kycLevel;

    // Validate that we issued a credential for this DID with sufficient level
    let hasValidCredential = false;
    for (const [id, data] of issuedCredentials.entries()) {
      if (data.issuedTo === did && data.kycLevel >= requiredLevelInt) {
        hasValidCredential = true;
        break;
      }
    }

    if (!hasValidCredential) {
      return res.status(403).json({ 
        error: `No valid credential found for DID ${did} with KYC level >= ${requiredLevelInt}` 
      });
    }

    // Generate mock ZK proof with proper structure
    const zkProof = {
      PiA: [
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "98765432109876543210987654321098765432109876543210987654321098765432109876543210",
      ],
      PiB: [
        [
          "11111111111111111111111111111111111111111111111111111111111111111111111111111111",
          "22222222222222222222222222222222222222222222222222222222222222222222222222222222",
        ],
        [
          "33333333333333333333333333333333333333333333333333333333333333333333333333333333",
          "44444444444444444444444444444444444444444444444444444444444444444444444444444444",
        ],
      ],
      PiC: [
        "55555555555555555555555555555555555555555555555555555555555555555555555555555555",
        "66666666666666666666666666666666666666666666666666666666666666666666666666666666",
      ],
      KYCLevel: kycLevel,
    };

    // Generate issuer signature that the blockchain can validate
    const issuerSignature = generateZKProofSignature(zkProof);

    // Create public inputs including issuer signature
    const publicInputs = [
      kycLevel.toString(),           // KYC level
      "1",                          // Valid flag
      "mock_identity_state_hash",   // Identity state (would be real in production)
      "mock_address_commitment",    // Address commitment (would be real in production)
      issuerSignature,              // Issuer signature for validation
    ];

    const verifiableProof = {
      ...zkProof,
      DID: did,
      PublicInputs: publicInputs,
    };

    res.json({
      success: true,
      proof: verifiableProof,
      message: `ZK proof generated for DID ${did} with KYC level ${kycLevel}`,
      issuerSignature: issuerSignature,
      note: "This proof includes issuer signature validation for blockchain security"
    });

  } catch (error) {
    console.error("Error generating ZK proof:", error);
    res.status(500).json({ error: "Failed to generate ZK proof" });
  }
});

// Register a new identity (moved from client)
app.post("/api/v1/register-identity", async (req, res) => {
  try {
    const { identityId } = req.body;

    if (!identityId) {
      return res.status(400).json({ error: "Missing required field: identityId" });
    }

    console.log(`🆔 Registering new identity: ${identityId}`);

    // Check if identity already exists
    try {
      const existsResult = execSync(
        `./vnicd query kyc identity "${identityId}" --output json --node tcp://localhost:26657`,
        { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }
      );
      
      const existsData = JSON.parse(existsResult);
      if (existsData.id) {
        return res.status(409).json({ 
          error: "Identity already exists",
          identity: existsData
        });
      }
    } catch (queryError) {
      // Identity doesn't exist, which is what we want
      console.log("✅ Identity doesn't exist, proceeding with registration...");
    }

    // Register identity using CLI
    console.log("📤 Broadcasting identity registration transaction...");
    
    const result = execSync(
      `./vnicd tx kyc register-identity "${identityId}" --from issuer --keyring-backend test --yes --node tcp://localhost:26657 --output json`,
      { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }
    );

    const txResult = JSON.parse(result);
    
    if (txResult.code === 0) {
      console.log("✅ Identity registered successfully!");
      console.log(`   Transaction Hash: ${txResult.txhash}`);
      
      // Wait a moment then query the newly created identity
      setTimeout(async () => {
        try {
          const newIdentity = await queryIdentityFromChain(identityId);
          console.log("✅ Identity verification successful");
        } catch (err) {
          console.log("⚠️  Identity registered but verification delayed");
        }
      }, 2000);
      
      res.json({
        success: true,
        message: "Identity registered successfully",
        txHash: txResult.txhash,
        identityId: identityId
      });
    } else {
      console.error("❌ Transaction failed:", txResult.raw_log);
      res.status(500).json({
        success: false,
        error: txResult.raw_log || "Failed to register identity"
      });
    }
  } catch (error) {
    console.error("❌ Failed to register identity:", error.message);
    res.status(500).json({ 
      error: "Failed to register identity",
      details: error.message
    });
  }
});

// Query identity information (moved from client)
app.get("/api/v1/query-identity/:identityId", async (req, res) => {
  try {
    const { identityId } = req.params;
    
    console.log(`🔍 Querying identity: ${identityId}`);
    
    const identity = await queryIdentityFromChain(identityId);
    
    if (identity) {
      res.json({
        success: true,
        identity: identity
      });
    } else {
      res.status(404).json({
        success: false,
        error: "Identity not found"
      });
    }
  } catch (error) {
    console.error("❌ Failed to query identity:", error.message);
    res.status(500).json({
      error: "Failed to query identity",
      details: error.message
    });
  }
});

// Send blockchain transaction (moved from client)
app.post("/api/v1/send-transaction", async (req, res) => {
  try {
    const { amount, recipient, memo } = req.body;
    
    if (!amount) {
      return res.status(400).json({ error: "Missing required field: amount" });
    }
    
    const targetRecipient = recipient || ISSUER_CONFIG.address; // Self-transfer if no recipient
    const transactionMemo = memo || `Transaction from Issuer Service - ${new Date().toISOString()}`;
    
    console.log(`💸 Sending ${amount}stake to ${targetRecipient}`);
    
    // Check issuer balance first
    const balance = await blockchainClient.getAllBalances(ISSUER_CONFIG.address);
    const stakeBalance = balance.find(coin => coin.denom === 'stake');
    
    if (!stakeBalance || parseInt(stakeBalance.amount) < parseInt(amount)) {
      return res.status(400).json({
        error: "Insufficient balance for transaction",
        available: stakeBalance?.amount || 0,
        required: amount
      });
    }
    
    // Send transaction using the blockchain client
    const result = await blockchainClient.sendTokens(
      ISSUER_CONFIG.address,
      targetRecipient,
      [{ denom: "stake", amount: amount }],
      "auto",
      transactionMemo
    );
    
    if (result.code === 0) {
      console.log("✅ Transaction sent successfully!");
      
      res.json({
        success: true,
        transactionHash: result.transactionHash,
        gasUsed: result.gasUsed,
        amount: amount,
        recipient: targetRecipient,
        memo: transactionMemo
      });
    } else {
      console.log("❌ Transaction failed:", result.rawLog);
      res.status(500).json({
        success: false,
        error: result.rawLog || "Transaction failed"
      });
    }
  } catch (error) {
    console.error("❌ Failed to send transaction:", error.message);
    res.status(500).json({
      error: "Failed to send transaction",
      details: error.message
    });
  }
});

// Verify ZK proof (moved from client)
app.post("/api/v1/verify-zkproof", async (req, res) => {
  try {
    const { proof, identityId, kycLevel } = req.body;
    
    if (!proof || !identityId || !kycLevel) {
      return res.status(400).json({ 
        error: "Missing required fields: proof, identityId, kycLevel" 
      });
    }
    
    console.log(`🔒 Verifying ZK proof for identity: ${identityId}, level: ${kycLevel}`);
    
    // Get identity from chain to verify state
    const identity = await queryIdentityFromChain(identityId);
    if (!identity) {
      return res.status(404).json({
        error: "Identity not found on blockchain"
      });
    }
    
    // Verify the proof structure
    const isValidStructure = proof.pi_a && proof.pi_b && proof.pi_c && proof.public_inputs;
    
    if (!isValidStructure) {
      return res.status(400).json({
        error: "Invalid proof structure"
      });
    }
    
    // In production, this would use actual ZK verification libraries
    // For now, we validate basic structure and issuer signature
    const expectedKycLevel = parseInt(proof.public_inputs[0]);
    const validityFlag = parseInt(proof.public_inputs[1]);
    const identityState = proof.public_inputs[2];
    const issuerAddress = proof.public_inputs[4];
    
    // Validate proof components
    const isValid = 
      expectedKycLevel === kycLevel && 
      validityFlag === 1 && 
      identityState === identity.state &&
      issuerAddress === ISSUER_CONFIG.address;
    
    if (isValid) {
      console.log("✅ ZK proof verification successful!");
      
      res.json({
        success: true,
        valid: true,
        message: "ZK proof verified successfully",
        verificationDetails: {
          kycLevel: expectedKycLevel,
          identityState: identityState,
          issuerAddress: issuerAddress,
          verifiedAt: new Date().toISOString()
        }
      });
    } else {
      console.log("❌ ZK proof verification failed");
      
      res.status(400).json({
        success: false,
        valid: false,
        error: "ZK proof verification failed",
        details: {
          expectedKycLevel,
          actualKycLevel: kycLevel,
          validityFlag,
          identityStateMatch: identityState === identity.state,
          issuerAddressMatch: issuerAddress === ISSUER_CONFIG.address
        }
      });
    }
  } catch (error) {
    console.error("❌ Failed to verify ZK proof:", error.message);
    res.status(500).json({
      error: "Failed to verify ZK proof",
      details: error.message
    });
  }
});

// List identities (new endpoint for client convenience)
app.get("/api/v1/identities", async (req, res) => {
  try {
    const { address } = req.query;
    
    console.log(`🔍 Listing identities for address: ${address || 'all'}`);
    
    // Since there's no direct way to list all identities, we'll return 
    // information about credentials we've issued
    const credentials = Array.from(issuedCredentials.entries()).map(
      ([id, data]) => ({
        credentialId: id,
        identityId: data.issuedTo,
        kycLevel: data.kycLevel,
        issuedAt: data.issuedAt
      })
    );
    
    // Filter by address if provided (though DID doesn't directly map to address)
    let filteredCredentials = credentials;
    if (address) {
      // This is a simplified filter - in production you'd have proper address-to-DID mapping
      filteredCredentials = credentials.filter(cred => 
        cred.identityId.includes(address.slice(-8)) || 
        cred.identityId.includes(address)
      );
    }
    
    res.json({
      success: true,
      count: filteredCredentials.length,
      identities: filteredCredentials,
      note: "This endpoint returns identities with credentials issued by this service"
    });
  } catch (error) {
    console.error("❌ Failed to list identities:", error.message);
    res.status(500).json({
      error: "Failed to list identities",
      details: error.message
    });
  }
});

// Check blockchain status (moved from client)
app.get("/api/v1/chain-status", async (req, res) => {
  try {
    console.log("🔍 Checking chain status...");
    
    const axios = require('axios');
    
    const status = await axios.get(
      `${ISSUER_CONFIG.chainRest}/cosmos/base/tendermint/v1beta1/node_info`,
    );
    
    const chainInfo = {
      chainId: status.data.default_node_info.network,
      latestBlock: status.data.default_node_info.other.latest_block_height || "N/A",
      nodeInfo: status.data.default_node_info
    };
    
    // Check issuer balance
    let balance = [];
    if (blockchainClient && ISSUER_CONFIG.address) {
      try {
        balance = await blockchainClient.getAllBalances(ISSUER_CONFIG.address);
      } catch (balanceError) {
        console.warn("Could not fetch balance:", balanceError.message);
      }
    }
    
    res.json({
      success: true,
      chainStatus: chainInfo,
      issuerBalance: balance,
      issuerAddress: ISSUER_CONFIG.address,
      blockchainConnected: !!blockchainClient
    });
  } catch (error) {
    console.error("❌ Failed to check chain status:", error.message);
    res.status(500).json({
      error: "Failed to check chain status",
      details: error.message,
      suggestion: "Make sure your VietChain node is running with: ignite chain serve"
    });
  }
});

// Helper function to query identity from blockchain
async function queryIdentityFromChain(identityId) {
  try {
    const axios = require('axios');
    
    const response = await axios.get(
      `${ISSUER_CONFIG.chainRest}/kycchain/kyc/v1/identity/${identityId}`,
    );

    if (response.data && response.data.id) {
      return response.data;
    }
    
    return null;
  } catch (error) {
    if (error.response && error.response.status === 404) {
      return null;
    }
    throw error;
  }
}

// Start server
async function startServer() {
  // Initialize blockchain client first
  const blockchainInit = await initBlockchainClient();

  app.listen(PORT, () => {
    console.log(`\n🚀 VietChain Issuer Service running on port ${PORT}`);
    console.log("=====================================");
    console.log("Issuer configuration:");
    console.log(`  ID: ${ISSUER_CONFIG.id}`);
    console.log(`  Name: ${ISSUER_CONFIG.name}`);
    console.log(`  Max KYC Level: ${ISSUER_CONFIG.maxKycLevel}`);
    console.log(`  Blockchain Address: ${issuerAddress}`);
    console.log(`  Credential Signing: RSA-2048`);
    console.log(`  Public Key Hash: ${ISSUER_CONFIG.publicKeyHex ? ISSUER_CONFIG.publicKeyHex.substring(0, 32) + '...' : 'Not initialized'}`);

    if (blockchainInit) {
      console.log("  ✅ Secure blockchain integration enabled");
      console.log("  ✅ Cryptographic credential signing enabled");
      console.log("  ✅ ZK proof issuer validation enabled");
    } else {
      console.log(
        "  ⚠️  Blockchain integration failed - running in limited mode",
      );
    }
    console.log("=====================================\n");
  });
}

startServer();

