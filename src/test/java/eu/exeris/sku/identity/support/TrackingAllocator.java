package eu.exeris.sku.identity.support;

import eu.exeris.kernel.spi.memory.AllocationHint;
import eu.exeris.kernel.spi.memory.LeakDetectionMode;
import eu.exeris.kernel.spi.memory.LoanedBuffer;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import eu.exeris.kernel.spi.memory.MemoryProvider;
import eu.exeris.kernel.spi.memory.MemoryProviderConfig;
import eu.exeris.kernel.spi.memory.MemoryStats;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A kernel allocator that counts what it hands out: every buffer allocated, every buffer finally released,
 * and every {@code close()} call made on a buffer, so a redundant close is visible even though the kernel's
 * buffers tolerate one. The memory itself comes from the kernel's own provider with leak detection on.
 */
public final class TrackingAllocator implements MemoryAllocator {

    private final MemoryAllocator delegate;
    private final AtomicLong allocated = new AtomicLong();
    private final AtomicLong finalReleases = new AtomicLong();
    private final List<AtomicInteger> closeCalls = new CopyOnWriteArrayList<>();

    private TrackingAllocator(MemoryAllocator delegate) {
        this.delegate = delegate;
    }

    /** An allocator over the kernel's memory provider found on the class path. */
    public static TrackingAllocator create() {
        MemoryProvider provider = ServiceLoader.load(MemoryProvider.class).findFirst().orElseThrow();
        return new TrackingAllocator(provider.createAllocator(
                MemoryProviderConfig.defaults().withLeakDetection(LeakDetectionMode.PARANOID)));
    }

    public long allocations() {
        return allocated.get();
    }

    public long finalReleases() {
        return finalReleases.get();
    }

    /** Buffers handed out and not yet finally released. */
    public long outstanding() {
        return allocated.get() - finalReleases.get();
    }

    /** The number of {@code close()} calls made on each buffer handed out, in allocation order. */
    public List<Integer> closeCalls() {
        return closeCalls.stream().map(AtomicInteger::get).toList();
    }

    private LoanedBuffer track(LoanedBuffer buffer) {
        allocated.incrementAndGet();
        buffer.addCloseAction(finalReleases::incrementAndGet);
        AtomicInteger calls = new AtomicInteger();
        closeCalls.add(calls);
        InvocationHandler counting = (proxy, method, args) -> {
            if (method.getName().equals("close") && method.getParameterCount() == 0) {
                calls.incrementAndGet();
            }
            try {
                return method.invoke(buffer, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        };
        return (LoanedBuffer) Proxy.newProxyInstance(LoanedBuffer.class.getClassLoader(),
                new Class<?>[] {LoanedBuffer.class}, counting);
    }

    @Override
    public LoanedBuffer allocate(AllocationHint hint) {
        return track(delegate.allocate(hint));
    }

    @Override
    public LoanedBuffer allocateNetwork(int estimatedBytes) {
        return track(delegate.allocateNetwork(estimatedBytes));
    }

    @Override
    public LoanedBuffer allocateCarrierSlab(int carrierIndex) {
        return track(delegate.allocateCarrierSlab(carrierIndex));
    }

    @Override
    public LoanedBuffer allocateInfrastructure(long sizeBytes) {
        return track(delegate.allocateInfrastructure(sizeBytes));
    }

    @Override
    public MemoryStats stats() {
        return delegate.stats();
    }

    @Override
    public void close() {
        delegate.close();
    }
}
