import com.fasterxml.jackson.databind.node.ObjectNode
import jp.co.soramitsu.crypto.ed25519.Ed25519Sha3
import jp.co.soramitsu.crypto.ed25519.EdDSAPrivateKey
import jp.co.soramitsu.crypto.ed25519.EdDSAPublicKey
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAGenParameterSpec
import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable.ED_25519
import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable.getByName
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec
import jp.co.soramitsu.sora.sdk.crypto.json.JSONEd25519Sha3SignatureSuite
import jp.co.soramitsu.sora.sdk.did.model.dto.DDO
import jp.co.soramitsu.sora.sdk.did.model.dto.DID
import jp.co.soramitsu.sora.sdk.did.model.dto.Options
import jp.co.soramitsu.sora.sdk.did.model.dto.authentication.Ed25519Sha3Authentication
import jp.co.soramitsu.sora.sdk.did.model.dto.publickey.Ed25519Sha3VerificationKey
import jp.co.soramitsu.sora.sdk.did.model.type.SignatureTypeEnum
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import java.security.KeyPair
import java.time.Instant
import javax.xml.bind.DatatypeConverter.parseHexBinary
import javax.xml.bind.DatatypeConverter.printHexBinary
import kotlin.random.Random
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    // declare cli
    val parser = ArgParser("ddo-gen")
    val didRaw by parser.option(
        ArgType.String,
        "did",
        "d",
        "DID to create DDO. If omitted, then new one will be created. Example `did:sora:alice`"
    )
    val secretKeyHex by parser.option(
        ArgType.String,
        "secret-key",
        "s",
        "Ed25519Sha3 secret key in hex encoding. If omitted, then new one will be created"
    )

    // parse args
    parser.parse(args)
    val did = when (didRaw) {
        null -> { DID.parse("did:sora:${randomHex()}") }
        else -> try {
            DID.parse(didRaw)
        } catch (ex: Exception) {
            println("Could not parse DID from `$didRaw`")
            exitProcess(1)
        }
    }
    val keypair = when (secretKeyHex) {
        null -> Ed25519Sha3().generateKeypair()
        else -> try {
            val sk = Ed25519Sha3.privateKeyFromBytes(parseHexBinary(secretKeyHex))
            require(sk is EdDSAPrivateKey) { "Private key must be an EdDSA" }
            val edParams = getByName(EdDSAGenParameterSpec(ED_25519).name)
            val pk = EdDSAPublicKey(EdDSAPublicKeySpec(sk.a, edParams))
            KeyPair(pk, sk)
        } catch (ex: Exception) {
            println("Could not parse secret key from hex `$secretKeyHex`")
            exitProcess(1)
        }
    }

    // create ddo
    val ddo = createDdo(did, keypair)

    // print output
    System.out.printf("DID %10s %s%n", "-->", did)
    System.out.printf("Secret key %s %s%n", "-->", printHexBinary(keypair.private.encoded).lowercase())
    System.out.printf("Public key %s %s%n", "-->", printHexBinary(keypair.public.encoded).lowercase())
    System.out.printf("DDO %10s %s%n", "-->", ddo)
}

private fun createDdo(did: DID, keyPair: KeyPair): ObjectNode {
    val publicKeyId = did.withFragment("keys-1")
    val options = Options.builder()
        .created(Instant.now())
        .creator(publicKeyId)
        .type(SignatureTypeEnum.Ed25519Sha3Signature)
        .nonce(randomHex())
        .build()
    val ddo = DDO.builder()
        .id(did)
        .created(Instant.now())
        .authentication(Ed25519Sha3Authentication(publicKeyId))
        .publicKey(Ed25519Sha3VerificationKey(publicKeyId, did, keyPair.public.encoded))
        .build()

    return JSONEd25519Sha3SignatureSuite().sign(
        ddo,
        keyPair.private as EdDSAPrivateKey,
        options
    )
}

private fun randomHex(length: Int = 16): String {
    val hexPower = "0123456789abcdef"
    return generateSequence { hexPower[Random.nextInt(hexPower.length)] }
        .take(length)
        .joinToString("")
}

