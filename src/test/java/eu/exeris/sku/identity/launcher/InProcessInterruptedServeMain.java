package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.process.ThrowingOnJoinPart;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs {@link IdentitySkuApplication#serve(java.util.Map)} on a thread of a JVM of its own whose host part is
 * parked before the composition starts (see {@link ThrowingOnJoinPart#PARK}), interrupts that thread while the
 * part is parked, and prints what the call returned. A background probe asks {@code /health} the whole time.
 *
 * <p>Prints {@code RETURNED=<bool>}, {@code STATUS=<n>}, {@code EVER_HEALTHY=<bool>}, {@code LEFTOVER=<names>}
 * and {@code SETTLED=<names>}.
 */
public final class InProcessInterruptedServeMain {

    private static final long BOUND_MILLIS = 90_000;
    private static final long SETTLE_MILLIS = 10_000;

    private InProcessInterruptedServeMain() {
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv("EXERIS_HTTP_PORT"));
        CountDownLatch parked = new CountDownLatch(1);
        PrintStream original = System.err;
        System.setErr(new PrintStream(new OutputStream() {
            private final StringBuilder line = new StringBuilder();

            @Override
            public void write(int b) {
                original.write(b);
                if (b == '\n') {
                    if (line.toString().contains(ThrowingOnJoinPart.PARKED_LINE)) {
                        parked.countDown();
                    }
                    line.setLength(0);
                } else {
                    line.append((char) b);
                }
            }
        }, true, StandardCharsets.UTF_8));

        Set<Thread> before = nonDaemon();
        AtomicInteger status = new AtomicInteger(-1);
        AtomicBoolean everHealthy = new AtomicBoolean();
        AtomicBoolean finished = new AtomicBoolean();
        Thread probe = new Thread(() -> {
            while (!finished.get()) {
                if (healthy(port)) {
                    everHealthy.set(true);
                }
            }
        }, "health-probe");
        probe.setDaemon(true);
        probe.start();
        Thread server = new Thread(() -> status.set(IdentitySkuApplication.serve(System.getenv())), "serve-under-test");
        server.start();

        if (!parked.await(BOUND_MILLIS, TimeUnit.MILLISECONDS)) {
            System.out.println("NEVER_PARKED status=" + status.get());
            System.exit(2);
        }
        server.interrupt();
        server.join(60_000);
        finished.set(true);
        probe.join(5_000);
        System.out.println("RETURNED=" + !server.isAlive());
        System.out.println("STATUS=" + status.get());
        System.out.println("EVER_HEALTHY=" + everHealthy.get());
        System.out.println("LEFTOVER=" + names(before));
        long settled = System.currentTimeMillis() + SETTLE_MILLIS;
        while (!names(before).isEmpty() && System.currentTimeMillis() < settled) {
            Thread.sleep(50);
        }
        System.out.println("SETTLED=" + names(before));
        System.out.flush();
        // A thread the kernel left behind must not keep a test waiting.
        Runtime.getRuntime().halt(0);
    }

    private static Set<Thread> nonDaemon() {
        Set<Thread> threads = new HashSet<>();
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

    private static boolean healthy(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 200);
            socket.setSoTimeout(1_000);
            OutputStream out = socket.getOutputStream();
            out.write("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = socket.getInputStream();
            return new String(in.readNBytes(12), StandardCharsets.US_ASCII).startsWith("HTTP/1.1 200");
        } catch (IOException e) {
            return false;
        }
    }
}
