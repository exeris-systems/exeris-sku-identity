package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/** What the serve tests share: probing the port and waiting for the service to answer. */
final class ServeSupport {

    private static final HttpClient CLIENT = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(2)).build();

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

    /** Waits until /health answers 200; fails with the output when the process exits or the time runs out. */
    static void awaitHealthy(LaunchedProcess process, int port) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new AssertionError("the service exited before it was healthy" + System.lineSeparator()
                        + process.output());
            }
            try {
                HttpResponse<String> response = CLIENT.send(
                        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/health"))
                                .timeout(Duration.ofSeconds(5)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    return;
                }
            } catch (Exception notUpYet) {
                // keep waiting
            }
            Thread.sleep(250);
        }
        throw new AssertionError("the service did not become healthy" + System.lineSeparator() + process.output());
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
