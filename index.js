const CONF = './config/'
require('dotenv').config({ path: CONF + '.env' })

const axios = require('axios')
const crypto = require('crypto')
const fs = require('fs').promises
const jose = require('jose')

const SD_PATH = process.argv.slice(2)[0] || CONF + 'self-description.json'
const selfDescription = require(SD_PATH)
const CURRENT_TIME = new Date().getTime()
const BASE_URL = process.env.BASE_URL || 'https://compliance.gaia-x.eu'
const API_VERSION = process.env.API_VERSION || '2206'

const OUTPUT_DIR = process.argv.slice(2)[1] || './output/'
createOutputFolder(OUTPUT_DIR)

const TYPE_API_ATH = {
  ServiceOfferingExperimental: 'service-offering',
  LegalPerson: 'participant',
}

function getApiVersionedUrl() {
  return `${BASE_URL}/v${API_VERSION}/api`
}

async function canonize(selfDescription) {
  const URL = `${getApiVersionedUrl()}/normalize`
  const { data } = await axios.post(URL, selfDescription)

  return data
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex')
}

async function sign(hash) {

  /*
  Key type: Public / Private key pairs (RSA, EC, OKP)
    Algorithms:
      RSA signature with PKCS #1 and SHA-2: RS256, RS384, RS512
      RSA PSS signature with SHA-2: PS256, PS384, PS512
      ECDSA signature with SHA-2: ES256, ES256K, ES384, ES512
      Edwards-curve DSA: EdDSA
   */
  console.log("Signing privateKey")

    // JSON Web Key (JWK ). “RSA”, “EC”, “OKP”, and “oct” key types are supported.
  const privateKey = await jose.importPKCS8(
    process.env.PRIVATE_KEY,
    process.env.SIGNATURE_ALGORITHM
  )

  if (process.env.SIGNATURE_ALGORITHM === "PS256") {
    console.log("Using PS256")
    try {
      // This supports RSA keys only
      const jws = await new jose.CompactSign(new TextEncoder().encode(hash))
          .setProtectedHeader({alg: 'PS256', b64: false, crit: ['b64']})
          .sign(privateKey)
      console.log("Finished signing")
      return jws
    } catch (error) {
      console.log(error)
    }

  }
  else if (process.env.SIGNATURE_ALGORITHM === "ES256") {
    console.log("Using ES256")
    try {
      const jws = await new jose.SignJWT({ 'urn:example:claim': true })
          .setProtectedHeader({ alg: 'ES256' })
          .sign(privateKey)
      console.log("Finished signing")
      return jws
    } catch (error) {
      console.log(error)
    }
  }
  else {
    message = "Unsupported SIGNATURE_ALGORITHM" + process.env.SIGNATURE_ALGORITHM + ". Exiting!"
    console.log(message)
    throw new Error(message)
  }
}

async function createProof(hash) {
  console.log("Creating proof")
  const proof = {
    type: 'JsonWebSignature2020',
    created: new Date(CURRENT_TIME).toISOString(),
    proofPurpose: 'assertionMethod',
    verificationMethod:
      process.env.VERIFICATION_METHOD ?? 'did:web:compliance.lab.gaia-x.eu',
    jws: await sign(hash)
  }
  console.log("Finished proof")
  return proof
}

async function verify(jwt) {
  const algorithm = process.env.SIGNATURE_ALGORITHM
  const x509 = await jose.importX509(process.env.CERTIFICATE, algorithm)
  const publicKeyJwk = await jose.exportJWK(x509)
  const pubkey = await jose.importJWK(publicKeyJwk, process.env.SIGNATURE_ALGORITHM)

  if (process.env.SIGNATURE_ALGORITHM === "PS256") {
    jws = jwt.jws.replace('..', `.${hash}.`)
    console.log("Using PS256")
    try {
      const result = await jose.compactVerify(jws, pubkey)
      return {
        protectedHeader: result.protectedHeader,
        content: new TextDecoder().decode(result.payload),
      }
    } catch (error) {
      console.error("PS256 verification failed: " + error)
    }

  }
  else if (process.env.SIGNATURE_ALGORITHM === "ES256") {
    console.log("Using ES256")
    console.log(jwt)
    try {

      const { payload, protectedHeader } = await jose.jwtVerify(jwt.jws, pubkey)

      console.log(payload)
      console.log(protectedHeader)
      return {
        protectedHeader: protectedHeader,
        payload: payload,
        content: payload
      }
    } catch (error) {
      console.error("ES256 verification failed: " + error)
    }
  }
  return {}
}

async function createSignedSdFile(selfDescription, proof) {
  const content = proof ? { ...selfDescription, proof } : selfDescription
  const status = proof ? 'self-signed' : 'complete'
  const type = proof
    ? selfDescription['type'].find((t) => t !== 'VerifiableCredential')
    : selfDescription.selfDescriptionCredential['type'].find(
        (t) => t !== 'VerifiableCredential'
      )
  const data = JSON.stringify(content, null, 2)
  const filename = `${OUTPUT_DIR}${CURRENT_TIME}_${status}_${type}.json`

  await fs.writeFile(filename, data)

  return filename
}

async function createDIDFile() {
  const algorithm = 'PS256'
  const x509 = await jose.importX509(process.env.CERTIFICATE, algorithm)
  const publicKeyJwk = await jose.exportJWK(x509)
  publicKeyJwk.alg = algorithm
  publicKeyJwk.x5u = process.env.X5U_URL

  const did = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: process.env.VERIFICATION_METHOD,
    verificationMethod: [
      {
        '@context': 'https://w3c-ccg.github.io/lds-jws2020/contexts/v1/',
        id: process.env.VERIFICATION_METHOD,
        type: 'JsonWebKey2020',
        controller: process.env.CONTROLLER,
        publicKeyJwk,
      },
    ],
    assertionMethod: [process.env.VERIFICATION_METHOD + '#JWK2020-RSA'],
  }

  const data = JSON.stringify(did, null, 2)
  const filename = `${OUTPUT_DIR}${CURRENT_TIME}_did.json`

  await fs.writeFile(filename, data)

  return filename
}

function logger(...msg) {
  console.log(msg.join(' '))
}

async function signSd(selfDescription, proof) {
  const URL = `${getApiVersionedUrl()}/sign`
  const { data } = await axios.post(URL, { ...selfDescription, proof })

  return data
}

async function verifySelfDescription(selfDescription) {
  const credentialType = selfDescription.selfDescriptionCredential['type'].find(
    (el) => el !== 'VerifiableCredential'
  )
  const type = TYPE_API_ATH[credentialType] || TYPE_API_ATH.LegalPerson
  const URL = `${getApiVersionedUrl()}/${type}/verify/raw`
  const { data } = await axios.post(URL, selfDescription)

  return data
}

async function createOutputFolder(dir) {
  try {
    await fs.access(dir)
  } catch (e) {
    await fs.mkdir(dir)
  }
}

async function main() {
  logger(`📝 Loaded ${SD_PATH}`)

  try {
    const canonizedSD = await canonize(selfDescription)

    const hash = sha256(canonizedSD)
    logger(`📈 Hashed canonized SD ${hash}`)

    const proof = await createProof(hash)
    logger(
      proof
        ? '🔒 SD signed successfully (local)'
        : '❌ SD signing failed (local)'
    )

    const verificationResult = await verify(proof)
    console.log(verificationResult)
    logger(
      verificationResult?.content === hash
        ? '✅ Verification successful (local)'
        : '❌ Verification failed (local)'
    )

    const filenameSignedSd = await createSignedSdFile(selfDescription, proof)
    logger(`📁 ${filenameSignedSd} saved`)

    const filenameDid = await createDIDFile()
    logger(`📁 ${filenameDid} saved`, '\n')

    // the following code only works if you hosted your created did.json
    logger('🔍 Checking Self Description with the Compliance Service...')

    const complianceCredential = await signSd(selfDescription, proof)
    logger(
      complianceCredential
        ? '🔒 SD signed successfully (compliance service)'
        : '❌ SD signing failed (compliance service)'
    )

    if (complianceCredential) {
      const completeSd = {
        selfDescriptionCredential: { ...selfDescription, proof },
        complianceCredential: complianceCredential.complianceCredential,
      }

      const verificationResultRemote = await verifySelfDescription(completeSd)
      logger(
        verificationResultRemote?.conforms === true
          ? '✅ Verification successful (compliance service)'
          : `❌ Verification failed (compliance service): ${verificationResultRemote.conforms}`
      )

      const filenameCompleteSd = await createSignedSdFile(completeSd)
      logger(`📁 ${filenameCompleteSd} saved`)
    }
  } catch (error) {
    console.dir('Something went wrong:')
    console.dir(error?.response?.data, { depth: null, colors: true })
  }
}

main()
