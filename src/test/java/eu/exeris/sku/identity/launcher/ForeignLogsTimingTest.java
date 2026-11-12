package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * When a secret becomes known, and what a reader of the secrets sees while another thread adds one. A record
 * is redacted with the secrets known when it is published: those learned before the record was created are
 * always among them, and the set is a snapshot, never a mixture.
 */
@DisplayName("ForeignLogs: secrets learned later, and logging threads against a learner")
class ForeignLogsTimingTest {

    private static final String W = LogRedaction.WITHHELD;

    private JulState state;
    private ForeignLogsTest.Capture capture;
    private final List<Logger> keep = new ArrayList<>();

    @BeforeEach
    void install() {
        state = new JulState();
        capture = new ForeignLogsTest.Capture();
        state.replaceRootHandlers(capture);
    }

    @AfterEach
    void restore() {
        state.close();
        keep.clear();
    }

    private Logger logger() {
        Logger logger = Logger.getLogger("third.party.timing." + SecretForms.lowerCaseMarker());
        logger.setLevel(Level.ALL);
        keep.add(logger);
        return logger;
    }

    @Test
    @DisplayName("A record logged before learn is not affected; after learn the password is withheld; the earlier record is not rewritten")
    void learnTakesEffectFromThenOn() {
        String known = SecretForms.marker();
        String password = SecretForms.marker();
        ForeignLogs.begin(known);
        Logger logger = logger();

        logger.log(Level.WARNING, "before " + password + " " + known);
        ForeignLogs.learn(password.toCharArray());
        logger.log(Level.WARNING, "after " + password + " " + known);

        assertThat(capture.messages()).containsExactly("before " + password + " " + W, "after " + W + " " + W);
    }

    @Test
    @DisplayName("learn of null, of an empty array and of a secret already known adds nothing")
    void learnIgnoresNothingAndDuplicates() {
        List<String> secrets = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            secrets.add(SecretForms.marker());
        }
        ForeignLogs.begin(secrets.toArray(String[]::new));
        Logger logger = logger();

        ForeignLogs.learn(null);
        ForeignLogs.learn(new char[0]);
        for (int i = 0; i < 20; i++) {
            ForeignLogs.learn(secrets.get(i % 8).toCharArray());
        }
        logger.log(Level.WARNING, "x " + secrets.get(3));

        assertThat(capture.only()).as("still eight secrets, so not the cap").isEqualTo("x " + W);
    }

    @Test
    @DisplayName("begin of a second command in the same JVM replaces the secrets of the first, learned ones included")
    void secondCommandReplacesTheSecrets() {
        String first = SecretForms.marker();
        String learned = SecretForms.marker();
        String second = SecretForms.marker();
        Logger logger = logger();
        ForeignLogs.begin(first);
        ForeignLogs.learn(learned.toCharArray());

        ForeignLogs.begin(second);
        logger.log(Level.WARNING, first + " " + learned + " " + second);

        assertThat(capture.only()).isEqualTo(first + " " + learned + " " + W);
    }

    @Test
    @DisplayName("16 logging threads against a learner: every secret learned before a record was created is withheld from it, and the secrets withheld are always a snapshot")
    void loggingThreadsAgainstALearner() throws Exception {
        int threads = 16;
        int rounds = 30;
        int perRoundMinimum = 80;
        int secretsPerRound = 8;
        Logger logger = logger();
        ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();
        AtomicInteger logged = new AtomicInteger();
        List<String> violations = new ArrayList<>();
        int checked = 0;
        int partial = 0;

        for (int round = 0; round < rounds; round++) {
            List<String> secrets = new ArrayList<>();
            for (int i = 0; i < secretsPerRound; i++) {
                secrets.add(SecretForms.marker());
            }
            capture.records.clear();
            ForeignLogs.begin();
            AtomicInteger learned = new AtomicInteger();
            AtomicBoolean done = new AtomicBoolean();
            CountDownLatch start = new CountDownLatch(1);
            List<Thread> all = new ArrayList<>();
            Thread learner = new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < secretsPerRound; i++) {
                        ForeignLogs.learn(secrets.get(i).toCharArray());
                        learned.set(i + 1);
                        java.util.concurrent.locks.LockSupport.parkNanos(200_000);
                    }
                } catch (Throwable t) {
                    failures.add(t);
                } finally {
                    done.set(true);
                }
            }, "learner");
            all.add(learner);
            for (int t = 0; t < threads; t++) {
                int id = t;
                all.add(new Thread(() -> {
                    try {
                        start.await();
                        int n = 0;
                        while (!done.get() || n < perRoundMinimum) {
                            int seen = learned.get();
                            logger.log(Level.WARNING, "t=" + id + " n=" + n + " k=" + seen + " | "
                                    + String.join(" ", secrets));
                            logged.incrementAndGet();
                            n++;
                        }
                    } catch (Throwable t2) {
                        failures.add(t2);
                    }
                }, "logger-" + t));
            }
            all.forEach(Thread::start);
            start.countDown();
            for (Thread thread : all) {
                thread.join(TimeUnit.SECONDS.toMillis(60));
                assertThat(thread.isAlive()).as(thread.getName() + " finished").isFalse();
            }

            for (String message : capture.messages()) {
                checked++;
                String verdict = verdict(message, secrets);
                if (verdict != null && violations.size() < 10) {
                    violations.add("round " + round + ": " + verdict + ": " + message.replaceAll("Mq\\w{22}", "<MARKER>"));
                } else if (message.contains("<withheld> Mq")) {
                    partial++;
                }
            }
        }

        assertThat(failures).as("exceptions in the threads").isEmpty();
        assertThat(violations).as("records that broke the snapshot rule").isEmpty();
        assertThat(checked).as("records checked").isEqualTo(logged.get()).isGreaterThanOrEqualTo(20_000);
        assertThat(partial).as("records published while the learner was between two secrets, so that the "
                + "interleaving was exercised").isPositive();
    }

    /** Null when the record respects the snapshot rule, else why not. */
    private static String verdict(String message, List<String> secrets) {
        int bar = message.indexOf('|');
        int k = Integer.parseInt(message.substring(message.indexOf("k=") + 2, message.indexOf(' ', message.indexOf("k="))));
        String[] tokens = message.substring(bar + 2).split(" ", -1);
        if (tokens.length != secrets.size()) {
            return "tokens " + tokens.length;
        }
        int withheld = 0;
        while (withheld < tokens.length && tokens[withheld].equals(W)) {
            withheld++;
        }
        for (int i = withheld; i < tokens.length; i++) {
            if (!tokens[i].equals(secrets.get(i))) {
                return "not a snapshot: token " + i + " is neither withheld nor its secret";
            }
        }
        if (withheld < k) {
            return "learned " + k + " secrets before the record but " + withheld + " are withheld";
        }
        return null;
    }
}
