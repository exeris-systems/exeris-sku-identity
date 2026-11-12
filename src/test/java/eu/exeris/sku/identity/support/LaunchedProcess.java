package eu.exeris.sku.identity.support;

import eu.exeris.sku.identity.launcher.IdentitySkuApplication;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The launcher in a JVM of its own, on the test classpath, with exactly the environment the test gives it
 * and nothing inherited. Its output goes to a file that is part of every failure message.
 */
public final class LaunchedProcess implements AutoCloseable {

    /** The variable naming the licence manifest the kernel verifies; set only on a launched process. */
    public static final String LICENCE_VARIABLE = "EXERIS_LICENSE_MANIFEST_PATH";

    /**
     * Where a test run is told the developer licence is. It is a name of its own so that the test JVM,
     * whose in-process tests of the licence gate need a kernel with no manifest, does not see one.
     */
    public static final String DEVELOPER_LICENCE_VARIABLE = "EXERIS_DEV_LICENSE_MANIFEST_PATH";

    private final Process process;
    private final Path log;

    private LaunchedProcess(Process process, Path log) {
        this.process = process;
        this.log = log;
    }

    /**
     * Starts the launcher.
     *
     * @param environment the whole environment of the process
     * @param arguments   the command line after the class name
     */
    public static LaunchedProcess start(Map<String, String> environment, String... arguments) throws IOException {
        return start(environment, List.of(), arguments);
    }

    /**
     * Starts the launcher with extra JVM options.
     *
     * @param environment the whole environment of the process
     * @param jvmOptions  options placed before the class path
     * @param arguments   the command line after the class name
     */
    public static LaunchedProcess start(Map<String, String> environment, List<String> jvmOptions,
                                        String... arguments) throws IOException {
        return startMain(IdentitySkuApplication.class.getName(), environment, jvmOptions, arguments);
    }

    /**
     * Starts another main class of the test class path in a JVM of its own, with the same isolation as the
     * launcher.
     *
     * @param mainClass   the class to run
     * @param environment the whole environment of the process
     * @param jvmOptions  options placed before the class path
     * @param arguments   the command line after the class name
     */
    public static LaunchedProcess startMain(String mainClass, Map<String, String> environment,
                                            List<String> jvmOptions, String... arguments) throws IOException {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("--enable-native-access=ALL-UNNAMED");
        command.addAll(jvmOptions);
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(mainClass);
        command.addAll(List.of(arguments));
        Path log = Files.createTempFile("identity-it-", ".log");
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile());
        builder.environment().clear();
        builder.environment().putAll(environment);
        return new LaunchedProcess(builder.start(), log);
    }

    /** A free local TCP port. */
    public static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /**
     * The environment that points a launcher at a database as the service role.
     *
     * @param database the database
     * @param port     the port to listen on
     * @param identity the identity settings, key material included
     */
    public static Map<String, String> serviceEnvironment(PostgresSupport.Database database, int port,
                                                         Map<String, String> identity) {
        Map<String, String> env = new HashMap<>(identity);
        env.put("EXERIS_DATABASE_URL", database.serviceUrl());
        env.put("EXERIS_DATABASE_USER", database.serviceUser());
        env.put("EXERIS_DATABASE_PASSWORD", database.servicePassword());
        env.put("EXERIS_HTTP_BIND_HOST", "127.0.0.1");
        env.put("EXERIS_HTTP_PORT", String.valueOf(port));
        return env;
    }

    public boolean isAlive() {
        return process.isAlive();
    }

    /** Waits for the exit and returns its status. */
    public int awaitExit(long seconds) throws InterruptedException {
        if (!process.waitFor(seconds, TimeUnit.SECONDS)) {
            throw new AssertionError("the process did not exit within " + seconds + " s" + System.lineSeparator()
                    + output());
        }
        return process.exitValue();
    }

    /** Asks the process to stop, as a termination signal does, and returns its exit status. */
    public int terminate(long seconds) throws InterruptedException {
        process.destroy();
        return awaitExit(seconds);
    }

    /**
     * Asks the process to stop, as a termination signal does, and measures the time until it is dead.
     *
     * @param seconds how long to wait before failing
     * @return the exit status and the time from the request to the death of the process
     */
    public Stopped terminateTimed(long seconds) throws InterruptedException {
        long start = System.nanoTime();
        process.destroy();
        int status = awaitExit(seconds);
        return new Stopped(status, java.time.Duration.ofNanos(System.nanoTime() - start));
    }

    /** How a process ended after it was asked to stop. */
    public record Stopped(int status, java.time.Duration took) {
    }

    /** Everything the process has written so far. */
    public String output() {
        try {
            return Files.readString(log, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "(output unreadable)";
        }
    }

    @Override
    public void close() {
        process.destroyForcibly();
        try {
            Files.deleteIfExists(log);
        } catch (IOException ignored) {
            // the file is in the temporary directory
        }
    }

    /** The log file, for a test that wants to keep it. */
    public File logFile() {
        return log.toFile();
    }
}
