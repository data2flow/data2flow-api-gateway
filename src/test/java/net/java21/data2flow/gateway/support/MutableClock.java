package net.java21.data2flow.gateway.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** 테스트용 시계(design/testing §3). {@code advanceBy}로만 시간이 흐른다 */
public final class MutableClock extends Clock {

    private volatile Instant now;
    private final ZoneId zone;

    private MutableClock(Instant now, ZoneId zone) {
        this.now = now;
        this.zone = zone;
    }

    public static MutableClock atUtc(String isoInstant) {
        return new MutableClock(Instant.parse(isoInstant), ZoneOffset.UTC);
    }

    public void advanceBy(Duration duration) {
        now = now.plus(duration);
    }

    public void setInstant(Instant instant) {
        now = instant;
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return new MutableClock(now, zone);
    }

    @Override
    public Instant instant() {
        return now;
    }
}
