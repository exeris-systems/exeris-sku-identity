package eu.exeris.sku.identity.launcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * The state of the JVM's logging found by a test, restored by {@link #close()}: the handlers and the
 * parent-handler flag of the root logger and of every logger that existed, the level of each, and the
 * secrets of {@link ForeignLogs}. A logger created during the test loses its handlers.
 */
final class JulState implements AutoCloseable {

    private record Saved(List<Handler> handlers, boolean useParent, Level level) {
    }

    private final Map<Logger, Saved> saved = new IdentityHashMap<>();

    JulState() {
        LogManager manager = LogManager.getLogManager();
        remember(manager.getLogger(""));
        for (String name : Collections.list(manager.getLoggerNames())) {
            remember(manager.getLogger(name));
        }
    }

    private void remember(Logger logger) {
        if (logger != null) {
            saved.put(logger, new Saved(List.of(logger.getHandlers()), logger.getUseParentHandlers(),
                    logger.getLevel()));
        }
    }

    /** Replaces the handlers of the root logger with the given ones. */
    void replaceRootHandlers(Handler... handlers) {
        Logger root = Logger.getLogger("");
        for (Handler existing : root.getHandlers()) {
            root.removeHandler(existing);
        }
        for (Handler handler : handlers) {
            root.addHandler(handler);
        }
    }

    @Override
    public void close() {
        ForeignLogs.begin();
        LogManager manager = LogManager.getLogManager();
        List<Logger> now = new ArrayList<>();
        now.add(manager.getLogger(""));
        for (String name : Collections.list(manager.getLoggerNames())) {
            Logger logger = manager.getLogger(name);
            if (logger != null) {
                now.add(logger);
            }
        }
        for (Logger logger : now) {
            for (Handler handler : logger.getHandlers()) {
                logger.removeHandler(handler);
            }
            Saved before = saved.get(logger);
            if (before != null) {
                before.handlers().forEach(logger::addHandler);
                logger.setUseParentHandlers(before.useParent());
                logger.setLevel(before.level());
            }
        }
    }
}
