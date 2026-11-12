---
title: "Stopping the launcher and redacting its log"
type: explanation
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-11-12
---

# Stopping the launcher and redacting its log

Why a kept-open connection can delay the stop of `serve`, why the redaction of the launcher's log withholds more than the credential it was looking for, and why the stop notice does not go through the logging framework. The statuses, the tables of what is withheld and the limits are in the [launcher reference](../reference/launcher.md).

## Why a kept-open connection delays the stop

On a termination signal `serve` stops answering, drains its capabilities and then asks the kernel to stop its subsystems. The last step waits for the kernel's HTTP connections to end. The kernel counts a keep-alive connection as busy while it is parked between requests when the last request on it was slow, meaning more than about 100 ms from the start of that connection's request-loop iteration to the end of the handler. That time includes how long the client took to send the request, so a client that pauses between requests on a connection it keeps open makes its own request look slow. A health probe that polls once a second does exactly that.

A connection counted as busy is not closed by the stop. The stop waits for the kernel's idle timeout to reclaim it, and the stopping thread spins on a CPU meanwhile. The idle timeout is the `idleTimeoutMillis` of the kernel's `HttpConfig`, 30 000 ms by default; the launcher does not set it, so the delay is bounded by that setting and by nothing the service does. This is [exeris-kernel issue 835](https://github.com/exeris-systems/exeris-kernel/issues/835), seen with kernel 0.13.1.

A service that no client holds a connection to has nothing to wait for. Closing the clients' connections before signalling the process, for example by taking the instance out of the load balancer's rotation first, removes the cause; the stop grace the reference asks for has to cover the idle timeout as well as the 15 s drain budget.

## Why the redaction withholds so much

The redaction knows two kinds of secret. A configured secret is known to the launcher, so every spelling of it is found wherever it occurs. Any other credential is recognised only by the shape around it, and a shape tells where a value begins much more reliably than where it ends.

An unquoted value after a password name is the hard case. A password can hold blanks, commas, `&` and quotes, and nothing in the text says which of them ends it. Ending the value at the first blank would leave the tail of `password=my secret pass` in the log; ending it at a comma would leave the tail of `password=a,b`. The redaction therefore treats the rest of the line as the value. The cost is readability: a driver message that dumps its properties, such as `{user=u, password=x, ssl=true}`, loses everything after the password. A line is the smallest unit that can be withheld without guessing, and a withheld line is the cheaper error than a published password.

A URL does not pay the cost. The password of an authority ends at the `@` that closes it, and the password of a query ends at the next `&`, `;` or white space, because those characters are not part of a URL's value. A URL therefore keeps its host, port, database and parameters, which is what an operator needs to see in a connection failure.

The same reasoning decides what the launcher redacts. Every text it did not write itself is passed through the redaction with the secrets configured for the command, because a driver can quote the connection URL it was given and a configuration message can quote a value. A driver also logs before any exception exists, through the JVM's logging, so the launcher rewrites the records of every logger it does not own the same way, and hands the driver only a URL it has parsed itself. The launcher's own constant lines and the class names it logs for failures whose message is not ours to print do not carry such text and are logged directly.

## Why the stop notice bypasses the logging framework

The line `Shutdown signal received, draining` is written to the standard error by the shutdown hook itself. The logging framework registers a shutdown hook of its own, and JVM shutdown hooks run concurrently with no order between them. The framework's hook removes the log handlers, so a record published from the launcher's hook can arrive after the handlers are gone and be dropped. Nothing closes the standard error stream during shutdown, so a line written there is not lost. The notice is the one line that tells an operator the process saw the signal, which is why it goes the way that cannot be dropped.
