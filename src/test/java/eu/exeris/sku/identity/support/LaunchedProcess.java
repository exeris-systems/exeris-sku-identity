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

    /** The variable naming the licence manifest the kernel verifies. */
    public static final String LICENCE_VARIABLE = "EXERIS_LICENSE_MANIFEST_PATH";

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
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("--enable-native-access=ALL-UNNAMED");
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(IdentitySkuApplication.class.getName());
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
