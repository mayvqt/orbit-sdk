using System.Runtime.InteropServices;

namespace Orbit.Sdk;

// Native elapsed-clock ABIs stay isolated from credential and grant state.
internal static class Clock
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Timespec { public long Seconds; public long Nanoseconds; }
    [StructLayout(LayoutKind.Sequential)]
    private struct MachTimebase { public uint Numerator; public uint Denominator; }

    [DllImport("libc", EntryPoint = "clock_gettime", SetLastError = true)]
    private static extern int ClockGetTime(int clockId, out Timespec value);

    [DllImport("api-ms-win-core-realtime-l1-1-1.dll", EntryPoint = "QueryInterruptTimePrecise")]
    private static extern void QueryInterruptTimePrecise(out ulong ticks);

    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "mach_timebase_info")]
    private static extern int MachTimebaseInfo(out MachTimebase info);

    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "mach_continuous_time")]
    private static extern ulong MachContinuousTime();

    private static readonly Lazy<MachTimebase> MacTimebase = new(() =>
    {
        if (MachTimebaseInfo(out var info) != 0 || info.Numerator == 0 || info.Denominator == 0)
            throw new OrbitException(OrbitError.ClockUncertain);
        return info;
    }, LazyThreadSafetyMode.ExecutionAndPublication);

    internal static bool TryConvertMachToTimeSpanTicks(ulong ticks, uint numerator, uint denominator, out long result)
    {
        result = 0;
        if (numerator == 0 || denominator == 0) return false;
        var nanoseconds = (UInt128)ticks * numerator / denominator;
        var timeSpanTicks = nanoseconds / 100;
        if (timeSpanTicks > (UInt128)long.MaxValue) return false;
        result = (long)timeSpanTicks;
        return true;
    }

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
            if (OperatingSystem.IsMacOS())
            {
                if (!Environment.Is64BitProcess)
                    throw new OrbitException(OrbitError.ClockUncertain);
                var ratio = MacTimebase.Value;
                if (!TryConvertMachToTimeSpanTicks(MachContinuousTime(), ratio.Numerator, ratio.Denominator, out var converted))
                    throw new OrbitException(OrbitError.ClockUncertain);
                return converted;
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
