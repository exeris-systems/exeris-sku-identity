package eu.exeris.sku.identity.launcher;

import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Runs {@link IdentitySkuApplication#serve(java.util.Map)} on a thread of a JVM of its own and sets that
 * thread's interrupt flag at the moment the launcher announces that it boots the kernel, that is after every
 * check the launcher makes and before the kernel is asked to boot. Prints {@code STATUS} and {@code FLAG}
 * (the flag after the call returned).
 */
public final class InterruptAtBootMain {

    private static final String BOOTING = "Booting Exeris Kernel subsystems";

    private InterruptAtBootMain() {
    }

    public static void main(String[] args) throws Exception {
        Logger.getLogger(IdentitySkuApplication.class.getName()).addHandler(new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getMessage() != null && record.getMessage().contains(BOOTING)) {
                    Thread.currentThread().interrupt();
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        });
        int[] status = {-1};
        boolean[] flag = new boolean[1];
        Thread server = new Thread(() -> {
            status[0] = IdentitySkuApplication.serve(System.getenv());
            flag[0] = Thread.currentThread().isInterrupted();
        }, "serve-under-test");
        server.start();
        server.join(120_000);
        System.out.println("RETURNED=" + !server.isAlive());
        System.out.println("STATUS=" + status[0]);
        System.out.println("FLAG=" + flag[0]);
        System.out.flush();
        Runtime.getRuntime().halt(0);
    }
}
