import com.wire.crypto.ConversationConfiguration
import com.wire.crypto.CoreCrypto
import com.wire.crypto.Invitee
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThatCode
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.random.Random.Default.nextInt

internal class CoreCryptoTest {

    companion object {
        private val chars = ('a'..'z') + ('A'..'Z') + ('0'..'9')
        val rndStr = { (1..20).map { chars[nextInt(0, chars.size)] }.joinToString("") }
        val tmpFile = { File.createTempFile(rndStr(), ".edb") }
        private val rndCentral = { CoreCrypto(tmpFile().absolutePath, rndStr(), rndStr()) }


        @OptIn(ExperimentalUnsignedTypes::class)
        private val rndBytes = { UByteArray(20) { nextInt(256).toUByte() }.toList() }
    }

    @Test
    fun `central should be buildable`() {
        assertThatCode { CoreCrypto(tmpFile().absolutePath, "alice-secret", "alice") }
            .doesNotThrowAnyException()
    }

    @Test
    fun `central should generate key packages`() {
        val requested = 100U
        assertThat(rndCentral().clientKeypackages(requested))
            .isNotEmpty
            .hasSize(requested.toInt())
            .noneMatch { it.isEmpty() }
    }

    @Test
    fun `central should create empty conversation`() {
        val config = ConversationConfiguration(
            extraMembers = emptyList(),
            admins = emptyList(),
            ciphersuite = null,
            keyRotationSpan = null,
        )
        val memberAddedMessages = rndCentral().createConversation(rndBytes(), config)
        assertThat(memberAddedMessages).isNull()
    }
}