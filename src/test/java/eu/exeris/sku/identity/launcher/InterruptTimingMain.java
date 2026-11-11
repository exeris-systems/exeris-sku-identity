package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.process.ThrowingOnJoinPart;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs {@link IdentitySkuApplication#serve(java.util.Map)} on a thread of a JVM of its own and interrupts that
 * thread at the moment the {@code MODE} environment variable names, see {@link #ENTRY}. A probe asks
 * {@code /health} throughout. Prints {@code RETURNED}, {@code STATUS}, {@code FLAG} (the interrupt flag of the
 * serving thread after the call returned), {@code EVER_HEALTHY} and {@code SETTLED} (non-daemon threads left).
 */
public final class InterruptTimingMain {

    /** The variable naming when the serving thread is interrupted. */
    public static final String MODE = "IDENTITY_TEST_TIMING";
    /** Before {@code serve} is called. */
    public static final String ENTRY = "entry";
    /** As soon as the kernel has booted and calls back into the launcher. */
    public static final String CALLBACK = "callback";
    /** While a host part is parked in the join of the transactional executor. */
    public static final String JOIN = "join";
    /** While the composition is starting. */
    public static final String START = "start";
    /** While the serving thread waits to hand the composition to the listener. */
    public static final String SERVE = "serve";
    /** After the service answers health. */
    public static final String HEALTHY = "healthy";

    private static final long BOUND_MILLIS = 90_000;

    private InterruptTimingMain() {
    }

    public static void main(String[] args) throws Exception {
        String mode = System.getenv(MODE);
        int port = Integer.parseInt(System.getenv("EXERIS_HTTP_PORT"));
        Set<Thread> before = nonDaemon();
        AtomicInteger status = new AtomicInteger(-1);
        AtomicBoolean flag = new AtomicBoolean();
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
        Thread server = new Thread(() -> {
            if (ENTRY.equals(mode)) {
                Thread.currentThread().interrupt();
            }
            status.set(IdentitySkuApplication.serve(System.getenv()));
            flag.set(Thread.currentThread().isInterrupted());
        }, "serve-under-test");
        server.start();

        switch (mode) {
            case JOIN -> interruptWhen(server, InterruptTimingMain::parkedInJoin, "parked");
            case CALLBACK -> interruptWhen(server, InterruptTimingMain::insideCallback, "callback");
            case START -> interruptWhen(server, InterruptTimingMain::insideTryStart, "tryStart");
            case HEALTHY -> {
                long deadline = System.currentTimeMillis() + BOUND_MILLIS;
                while (!everHealthy.get() && server.isAlive() && System.currentTimeMillis() < deadline) {
                    Thread.sleep(20);
                }
                System.out.println("INTERRUPTED_WHEN=healthy " + everHealthy.get());
                server.interrupt();
            }
            default -> {
                // ENTRY and SERVE interrupt on their own
            }
        }
        server.join(60_000);
        finished.set(true);
        probe.join(5_000);
        System.out.println("RETURNED=" + !server.isAlive());
        System.out.println("STATUS=" + status.get());
        System.out.println("FLAG=" + flag.get());
        System.out.println("EVER_HEALTHY=" + everHealthy.get());
        long settled = System.currentTimeMillis() + 10_000;
        while (!names(before).isEmpty() && System.currentTimeMillis() < settled) {
            Thread.sleep(50);
        }
        System.out.println("SETTLED=" + names(before));
        System.out.flush();
        Runtime.getRuntime().halt(0);
    }

    private interface Where {
        boolean test(StackTraceElement[] stack);
    }

    private static boolean parkedInJoin(StackTraceElement[] stack) {
        for (StackTraceElement frame : stack) {
            if (frame.getClassName().equals(ThrowingOnJoinPart.class.getName()) && frame.getMethodName().equals("joinTransactionsOf")) {
                return true;
            }
        }
        return false;
    }

    private static boolean insideCallback(StackTraceElement[] stack) {
        for (StackTraceElement frame : stack) {
            if (frame.getClassName().equals(IdentitySkuApplication.class.getName()) && frame.getMethodName().startsWith("lambda$boot")) {
                return true;
            }
        }
        return false;
    }

    private static boolean insideTryStart(StackTraceElement[] stack) {
        for (StackTraceElement frame : stack) {
            if (frame.getClassName().equals("eu.exeris.sku.identity.IdentityComposition")
                    && (frame.getMethodName().equals("tryStart") || frame.getMethodName().equals("beginStart"))) {
                return true;
            }
        }
        return false;
    }

    /** Polls the serving thread's stack and interrupts it the first time {@code where} holds. */
    private static void interruptWhen(Thread server, Where where, String label) throws InterruptedException {
        long deadline = System.currentTimeMillis() + BOUND_MILLIS;
        while (server.isAlive() && System.currentTimeMillis() < deadline) {
            if (where.test(server.getStackTrace())) {
                server.interrupt();
                System.out.println("INTERRUPTED_IN=" + label);
                return;
            }
        }
        System.out.println("NEVER_SEEN=" + label);
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
            out.write("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = socket.getInputStream();
            return new String(in.readNBytes(12), StandardCharsets.US_ASCII).startsWith("HTTP/1.1 200");
        } catch (IOException e) {
            return false;
        }
    }
}
