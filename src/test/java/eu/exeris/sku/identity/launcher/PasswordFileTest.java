package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.PASSWORD_FILE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@DisplayName("Password file of the bootstrap-owner command")
class PasswordFileTest {

    private static final PasswordPolicy POLICY = new PasswordPolicy(12, 64);

    private static String longEnough() {
        return "pw-" + "x".repeat(20);
    }

    private static char[] read(Path file, LauncherEnvironment in) {
        return PasswordFile.read(file, POLICY, in);
    }

    private static LauncherEnvironment env() {
        return new LauncherEnvironment(Map.of());
    }

    @Test
    @DisplayName("The content minus trailing LF or CRLF is the password; inner and leading whitespace stay")
    void trailingLineBreaksAreStripped(@TempDir Path dir) throws IOException {
        String password = " inner space  " + longEnough();
        for (String ending : new String[] {"", "\n", "\r\n", "\r\n\r\n", "\n\n"}) {
            LauncherEnvironment in = env();
            char[] read = read(BootstrapOwnerSupport.passwordFile(dir, password + ending), in);

            assertThat(in.problems()).isEmpty();
            assertThat(read).containsExactly(password.toCharArray());
        }
    }

    @Test
    @DisplayName("Multi-byte UTF-8 is decoded to characters")
    void utf8IsDecoded(@TempDir Path dir) throws IOException {
        String password = "zażółć-gęślą-jaźń-" + longEnough();
        LauncherEnvironment in = env();

        char[] read = read(BootstrapOwnerSupport.passwordFile(dir, password + "\n"), in);

        assertThat(in.problems()).isEmpty();
        assertThat(read).containsExactly(password.toCharArray());
    }

    @Test
    @DisplayName("A missing file, a directory, an empty file and a file of line breaks are each refused, naming the key")
    void unusableFiles(@TempDir Path dir) throws IOException {
        Path[] files = {dir.resolve("absent"), dir, BootstrapOwnerSupport.passwordFile(dir, ""),
                BootstrapOwnerSupport.passwordFile(dir, "\n\r\n\n")};
        for (Path file : files) {
            LauncherEnvironment in = env();

            assertThat(read(file, in)).isNull();
            assertThat(in.problems()).singleElement().asString().contains(PASSWORD_FILE);
        }
    }

    @Test
    @DisplayName("Any group or other permission bit is refused on a POSIX filesystem, and the content is not read")
    void permissions(@TempDir Path dir) throws IOException {
        assumeTrue(Files.getFileStore(dir).supportsFileAttributeView("posix"));
        for (String mode : new String[] {"rw-r-----", "rw----r--", "rw-rw----", "rw-------".replace("-------", "------x"),
                "rwx---r-x"}) {
            Path file = BootstrapOwnerSupport.passwordFile(dir, longEnough().getBytes(StandardCharsets.UTF_8), mode);
            LauncherEnvironment in = env();

            assertThat(read(file, in)).as(mode).isNull();
            assertThat(in.problems()).as(mode).singleElement().asString().contains(PASSWORD_FILE)
                    .doesNotContain(longEnough());
        }
        for (String mode : new String[] {"r--------", "rw-------"}) {
            LauncherEnvironment in = env();

            assertThat(read(BootstrapOwnerSupport.passwordFile(dir, longEnough().getBytes(StandardCharsets.UTF_8),
                    mode), in)).as(mode).isNotNull();
            assertThat(in.problems()).as(mode).isEmpty();
        }
    }

    @Test
    @DisplayName("A symbolic link to an owner-only file is followed")
    void linksAreFollowed(@TempDir Path dir) throws IOException {
        Path target = BootstrapOwnerSupport.passwordFile(dir, longEnough());
        Path link = dir.resolve("link");
        Files.createSymbolicLink(link, target);
        LauncherEnvironment in = env();

        assertThat(read(link, in)).containsExactly(longEnough().toCharArray());
        assertThat(in.problems()).isEmpty();
    }

    @Test
    @DisplayName("The length window is [min, max] in characters, boundaries included, and the message names no content")
    void lengthWindow(@TempDir Path dir) throws IOException {
        for (int length : new int[] {1, 11, 65, 200}) {
            String content = "q".repeat(length);
            LauncherEnvironment in = env();

            assertThat(read(BootstrapOwnerSupport.passwordFile(dir, content + "\n"), in)).as("" + length).isNull();
            assertThat(in.problems()).as("" + length).singleElement().asString()
                    .contains(PASSWORD_FILE).contains("12").contains("64").doesNotContain(content);
        }
        for (int length : new int[] {12, 64}) {
            LauncherEnvironment in = env();

            assertThat(read(BootstrapOwnerSupport.passwordFile(dir, "q".repeat(length)), in)).as("" + length)
                    .hasSize(length);
            assertThat(in.problems()).isEmpty();
        }
    }

    @Test
    @DisplayName("A file far larger than any password is refused")
    void hugeFile(@TempDir Path dir) throws IOException {
        LauncherEnvironment in = env();

        assertThat(read(BootstrapOwnerSupport.passwordFile(dir, "z".repeat(10_000_000)), in)).isNull();
        assertThat(in.problems()).singleElement().asString().contains(PASSWORD_FILE);
    }

    @Test
    @DisplayName("Content that is not valid UTF-8 is refused")
    void invalidUtf8(@TempDir Path dir) throws IOException {
        byte[] bad = new byte[20];
        java.util.Arrays.fill(bad, (byte) 'a');
        bad[7] = (byte) 0xC3;
        bad[8] = (byte) 0x28;
        LauncherEnvironment in = env();

        assertThat(read(BootstrapOwnerSupport.passwordFile(dir, bad, "rw-------"), in)).isNull();
        assertThat(in.problems()).singleElement().asString().contains(PASSWORD_FILE).containsIgnoringCase("utf-8");
    }
}
