package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** What the serve tests share: probing the port and waiting for the service to answer. */
final class ServeSupport {

    private ServeSupport() {
    }

    /** Whether something accepts a TCP connection on the loopback port. */
    static boolean accepts(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 500);
            return true;
        } catch (IOException refused) {
            return false;
        }
    }

    /** The environment of a development service over the database, a booting kernel excepted. */
    static Map<String, String> environment(PostgresSupport.Database database, int port, String directory) {
        Map<String, String> env = LaunchedProcess.serviceEnvironment(database, port, TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", directory);
        return env;
    }

    /** The same, with the developer licence a booting kernel needs; fails when the run was given none. */
    static Map<String, String> licensedEnvironment(PostgresSupport.Database database, int port, String directory) {
        String manifest = System.getenv(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE);
        if (manifest == null || manifest.isBlank()) {
            throw new AssertionError(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE + " is not set: a developer "
                    + "licence entitling exeris-sku-identity and its nine commercial capabilities is required "
                    + "to boot the kernel");
        }
        Map<String, String> env = environment(database, port, directory);
        env.put(LaunchedProcess.LICENCE_VARIABLE, manifest);
        return env;
    }

    /** The line the launcher logs once the service has been handed to the kernel's listener. */
    static final String RUNNING_LINE = "Exeris Identity running on";

    /**
     * Waits for the launcher's "running on" line, which is logged after the service answers requests; fails
     * with the output when the process exits first or the time runs out. Nothing connects to the port
     * meanwhile: a connection that is answered 503 during the start and kept alive holds the kernel's stop
     * until its idle timeout.
     */
    static void awaitRunning(LaunchedProcess process) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        while (System.nanoTime() < deadline) {
            if (process.output().contains(RUNNING_LINE)) {
                return;
            }
            if (!process.isAlive()) {
                throw new AssertionError("the service exited before it was running" + System.lineSeparator()
                        + process.output());
            }
            Thread.sleep(25);
        }
        throw new AssertionError("the service did not start running" + System.lineSeparator() + process.output());
    }

    /**
     * Waits until the service is running, then checks that /health answers 200 on a connection that is
     * closed after the request. Only after the "running on" line is the service probed, and never on a kept
     * connection, so no connection has seen a 503.
     */
    static void awaitHealthy(LaunchedProcess process, int port) throws Exception {
        awaitRunning(process);
        int status = get(port, "/health");
        if (status != 200) {
            throw new AssertionError("/health answered " + status + " after the service logged that it runs"
                    + System.lineSeparator() + process.output());
        }
    }

    /** One request on a connection of its own that the server is asked to close; the status it answered. */
    static int get(int port, String path) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 2_000);
            socket.setSoTimeout(5_000);
            socket.getOutputStream().write(("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            String status = new String(socket.getInputStream().readNBytes(12), StandardCharsets.US_ASCII);
            return Integer.parseInt(status.substring(9, 12));
        }
    }

    /** A connection that stays open between requests, so that the server's idea of a kept-alive client holds. */
    static final class KeptAlive implements AutoCloseable {

        private final Socket socket = new Socket();
        private final InputStream in;

        KeptAlive(int port) throws IOException {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 2_000);
            socket.setSoTimeout(5_000);
            in = socket.getInputStream();
        }

        /** Sends one GET and reads the whole answer, which must carry a Content-Length. */
        int get(String path) throws IOException {
            socket.getOutputStream().write(("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            StringBuilder head = new StringBuilder();
            while (!head.toString().endsWith("\r\n\r\n")) {
                int b = in.read();
                if (b < 0) {
                    throw new IOException("the server closed the connection");
                }
                head.append((char) b);
            }
            int length = 0;
            for (String line : head.toString().split("\r\n")) {
                if (line.regionMatches(true, 0, "Content-Length:", 0, 15)) {
                    length = Integer.parseInt(line.substring(15).trim());
                }
            }
            in.readNBytes(length);
            return Integer.parseInt(head.substring(9, 12));
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** Waits for the exit; on a timeout destroys the process and fails with its output. */
    static int awaitExitOrDestroy(LaunchedProcess process, long seconds) throws InterruptedException {
        try {
            return process.awaitExit(seconds);
        } catch (AssertionError stillAlive) {
            process.close();
            throw new AssertionError("serve hung: still alive after " + seconds + " s, destroyed"
                    + System.lineSeparator() + process.output(), stillAlive);
        }
    }
}
