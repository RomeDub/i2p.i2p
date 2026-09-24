package net.i2p;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.*;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 2)
@Fork(3)
@State(Scope.Thread)
public class NonceTidyBench {
    private static final int MAX = 1024;
    private final ConcurrentHashMap<Integer, Integer> map = new ConcurrentHashMap<Integer, Integer>();
    private final AtomicInteger counter = new AtomicInteger();
    private int value;

    @Setup
    public void setup() {
        for (int i = 0; i < 128; i++)
            map.put(i, i);
    }

    @Benchmark
    public int sizeCheck() {
        if (map.size() > MAX)
            map.clear();
        return ++value;
    }

    @Benchmark
    public int counterCheck() {
        if (counter.incrementAndGet() % 16 == 0)
            map.clear();
        return ++value;
    }
}
