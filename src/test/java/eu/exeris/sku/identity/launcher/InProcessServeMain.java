package eu.exeris.sku.identity.launcher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs {@link IdentitySkuApplication#serve(Map)} on a thread of a JVM of its own, interrupts that thread once
 * the service answers, and prints what the call returned and which non-daemon threads it left behind. The
 * licence manifest is read by the kernel from the process environment, which the test JVM must not have.
 *
 * <p>Prints {@code STATUS=<n>}, {@code LEFTOVER=<names>} and {@code SETTLED=<names>}; the last is taken after
 * the threads were given time to end.
 */
public final class InProcessServeMain {

    private static final long HEALTH_BOUND_MILLIS = 90_000;
    private static final long SETTLE_MILLIS = 10_000;

    private InProcessServeMain() {
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv("EXERIS_HTTP_PORT"));
        Set<Thread> before = nonDaemon();
        AtomicInteger status = new AtomicInteger(-1);
        Thread server = new Thread(() -> status.set(IdentitySkuApplication.serve(System.getenv())), "serve-under-test");
        server.start();

        long deadline = System.currentTimeMillis() + HEALTH_BOUND_MILLIS;
        while (!healthy(port)) {
            if (!server.isAlive() || System.currentTimeMillis() > deadline) {
                System.out.println("NEVER_HEALTHY status=" + status.get());
                System.exit(2);
            }
            Thread.sleep(100);
        }
        server.interrupt();
        server.join(60_000);
        System.out.println("RETURNED=" + !server.isAlive());
        System.out.println("STATUS=" + status.get());
        System.out.println("LEFTOVER=" + names(before));

        long settled = System.currentTimeMillis() + SETTLE_MILLIS;
        while (!names(before).isEmpty() && System.currentTimeMillis() < settled) {
            Thread.sleep(50);
        }
        System.out.println("SETTLED=" + names(before));
        System.out.flush();
        // The process is ended explicitly: a thread the kernel left behind must not keep a test waiting.
        Runtime.getRuntime().halt(0);
    }

    private static Set<Thread> nonDaemon() {
        Set<Thread> threads = new java.util.HashSet<>();
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.isAlive() && !thread.isDaemon()) {
                threads.add(thread);
            }
        }
        return threads;
    }

    private static Set<String> names(Set<Thread> before) {
        Set<String> names = new TreeSet<>();
        for (Thread thread : nonDaemon()) {
            if (!before.contains(thread) && thread.getName() != null && !thread.getName().equals("serve-under-test")) {
                names.add(thread.getName());
            }
        }
        return names;
    }

    /** One request on a connection that is closed afterwards: a kept-alive connection would outlive the stop. */
    private static boolean healthy(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 500);
            socket.setSoTimeout(2_000);
            OutputStream out = socket.getOutputStream();
            out.write(("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] head = in.readNBytes(12);
            return new String(head, StandardCharsets.US_ASCII).startsWith("HTTP/1.1 200");
        } catch (IOException e) {
            return false;
        }
    }
}
