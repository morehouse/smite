//! Statistical summaries for benchmark timings.

use std::time::Duration;

/// Per-execution latency summary, all fields in nanoseconds via [`Duration`].
pub struct LatencyStats {
    pub min: Duration,
    pub mean: Duration,
    pub median: Duration,
    pub p99: Duration,
    pub max: Duration,
}

impl LatencyStats {
    /// Computes summary statistics, sorting `latencies` in place.
    pub fn summarize(latencies: &mut [Duration]) -> Self {
        assert!(!latencies.is_empty(), "latencies must be non-empty");
        latencies.sort_unstable();

        Self {
            min: latencies[0],
            mean: avg_duration(latencies.iter().copied()),
            median: percentile(latencies, 50),
            p99: percentile(latencies, 99),
            max: latencies[latencies.len() - 1],
        }
    }
}

/// Returns the value at the given percentile from a sorted slice.
pub fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    assert!(!sorted.is_empty(), "sorted must be non-empty");
    assert!(pct <= 100, "percentile must be <= 100");
    // Nearest-rank on a zero-based slice: rank ceil(pct/100 * n) mapped to index.
    let rank = (pct * sorted.len()).div_ceil(100);
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

/// Returns the sample mean and standard deviation of `values`.
///
/// Standard deviation uses Bessel's correction (n-1); with a single value it is
/// `0.0`.
// Run counts are tiny, so usize->f64 precision loss cannot occur in practice.
#[allow(clippy::cast_precision_loss)]
pub fn mean_stddev(values: &[f64]) -> (f64, f64) {
    assert!(!values.is_empty(), "values must be non-empty");
    let n = values.len();
    let mean = values.iter().sum::<f64>() / n as f64;
    if n < 2 {
        return (mean, 0.0);
    }
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
    (mean, variance.sqrt())
}

/// Averages an iterator of durations (nanosecond precision).
pub fn avg_duration(durations: impl Iterator<Item = Duration>) -> Duration {
    let mut sum = 0u128;
    let mut count = 0u128;
    for d in durations {
        sum += d.as_nanos();
        count += 1;
    }
    assert!(count > 0, "durations must be non-empty");
    Duration::from_nanos(u64::try_from(sum / count).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn percentile_nearest_rank() {
        let mut v: Vec<Duration> = (1..=100).map(ms).collect();
        v.sort_unstable();
        assert_eq!(percentile(&v, 0), ms(1));
        assert_eq!(percentile(&v, 50), ms(50));
        assert_eq!(percentile(&v, 99), ms(99));
        assert_eq!(percentile(&v, 100), ms(100));
    }

    #[test]
    fn percentile_single_element() {
        let v = vec![ms(7)];
        assert_eq!(percentile(&v, 50), ms(7));
        assert_eq!(percentile(&v, 99), ms(7));
    }

    #[test]
    fn latency_stats_basic() {
        let mut v = vec![ms(4), ms(1), ms(3), ms(2)];
        let stats = LatencyStats::summarize(&mut v);
        assert_eq!(stats.min, ms(1));
        assert_eq!(stats.max, ms(4));
        // mean of 1..=4 ms = 2.5 ms
        assert_eq!(stats.mean, Duration::from_micros(2_500));
        assert_eq!(stats.median, ms(2));
    }

    #[test]
    fn latency_stats_single_element() {
        let mut v = vec![ms(7)];
        let stats = LatencyStats::summarize(&mut v);
        assert_eq!(stats.min, ms(7));
        assert_eq!(stats.mean, ms(7));
        assert_eq!(stats.median, ms(7));
        assert_eq!(stats.p99, ms(7));
        assert_eq!(stats.max, ms(7));
    }

    #[test]
    fn mean_stddev_single_value_has_zero_spread() {
        let (mean, stddev) = mean_stddev(&[42.0]);
        assert!((mean - 42.0).abs() < 1e-9);
        assert!(stddev.abs() < 1e-9);
    }

    #[test]
    fn mean_stddev_computes_sample_stddev() {
        // For [2, 4, 4, 4, 5, 5, 7, 9]: mean 5, sample stddev ~2.138.
        let (mean, stddev) = mean_stddev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert!((mean - 5.0).abs() < 1e-9, "mean was {mean}");
        assert!((stddev - 2.1380).abs() < 1e-3, "stddev was {stddev}");
    }

    #[test]
    fn avg_duration_averages_nanoseconds() {
        let avg = avg_duration([ms(10), ms(20), ms(30)].into_iter());
        assert_eq!(avg, ms(20));
    }

    #[test]
    fn avg_duration_prevents_overflow() {
        // Each value is 1e19 ns; the sum (2e19) overflows a u64 accumulator but
        // fits in the u128 one, so the average comes back exact.
        let big = Duration::from_secs(10_000_000_000);
        let avg = avg_duration([big, big].into_iter());
        assert_eq!(avg, big);
    }
}
