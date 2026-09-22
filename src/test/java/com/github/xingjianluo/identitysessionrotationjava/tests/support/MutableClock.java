package com.github.xingjianluo.identitysessionrotationjava.tests.support;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * Controllable clock for tests: starts at a fixed instant and only moves
 * when a test explicitly advances it, making expiry deterministic.
 */
public class MutableClock extends Clock {

    private Instant now;

    public MutableClock(Instant start) {
        this.now = start;
    }

    public static MutableClock startAt(Instant start) {
        return new MutableClock(start);
    }

    public void advanceSeconds(long seconds) {
        this.now = now.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Instant instant() {
        return now;
    }
}
