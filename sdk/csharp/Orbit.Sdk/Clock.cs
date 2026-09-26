using System.Runtime.InteropServices;

namespace Orbit.Sdk;

// Native elapsed-clock ABIs stay isolated from credential and grant state.
internal static class Clock
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Timespec { public long Seconds; public long Nanoseconds; }

    [DllImport("libc", EntryPoint = "clock_gettime", SetLastError = true)]
    private static extern int ClockGetTime(int clockId, out Timespec value);

    [DllImport("api-ms-win-core-realtime-l1-1-1.dll", EntryPoint = "QueryInterruptTimePrecise")]
    private static extern void QueryInterruptTimePrecise(out ulong ticks);

    internal static long ElapsedTicks()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                // Windows interrupt-time units already match TimeSpan (100 ns).
                // The biased clock includes time spent in sleep and hibernation.
                QueryInterruptTimePrecise(out var ticks);
                return checked((long)ticks);
            }
            if (!OperatingSystem.IsLinux() || !Environment.Is64BitProcess)
                throw new OrbitException(OrbitError.ClockUncertain);
            // CLOCK_BOOTTIME includes suspend, unlike CLOCK_MONOTONIC.
            if (ClockGetTime(7, out var value) != 0 || value.Seconds < 0 ||
                value.Nanoseconds is < 0 or >= 1_000_000_000)
                throw new OrbitException(OrbitError.ClockUncertain);
            return checked(value.Seconds * TimeSpan.TicksPerSecond + value.Nanoseconds / 100);
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or OverflowException)
        {
            throw new OrbitException(OrbitError.ClockUncertain);
        }
    }

    internal static ClockStart Capture() => new(ElapsedTicks(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
}

internal readonly record struct ClockStart(long ElapsedTicks, long WallSeconds);

internal sealed class ClockAnchor(long serverSeconds, ClockStart start)
{
    internal long ServerSeconds => serverSeconds;
    internal long WallSeconds => start.WallSeconds;
    internal long Now()
    {
        try
        {
            var elapsed = checked(Clock.ElapsedTicks() - start.ElapsedTicks);
            if (elapsed < 0) throw new OrbitException(OrbitError.ClockUncertain);
            var seconds = elapsed / TimeSpan.TicksPerSecond;
            var expected = checked(start.WallSeconds + seconds);
            if (Math.Abs(checked(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - expected)) > 30)
                throw new OrbitException(OrbitError.ClockUncertain);
            return checked(serverSeconds + seconds);
        }
        catch (OverflowException) { throw new OrbitException(OrbitError.ClockUncertain); }
    }
}
