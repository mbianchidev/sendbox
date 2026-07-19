use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Summary {
    pub count: usize,
    pub minimum: f64,
    pub maximum: f64,
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub confidence_interval_95: [f64; 2],
}

#[must_use]
pub fn summarize(samples: &[f64]) -> Option<Summary> {
    if samples.is_empty() || samples.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let count = sorted.len();
    let mean = sorted.iter().sum::<f64>() / count as f64;
    let variance = if count > 1 {
        sorted
            .iter()
            .map(|value| {
                let difference = value - mean;
                difference * difference
            })
            .sum::<f64>()
            / (count - 1) as f64
    } else {
        0.0
    };
    let margin = 1.96 * variance.sqrt() / (count as f64).sqrt();
    Some(Summary {
        count,
        minimum: sorted[0],
        maximum: sorted[count - 1],
        mean,
        p50: percentile(&sorted, 0.50),
        p95: percentile(&sorted, 0.95),
        p99: percentile(&sorted, 0.99),
        confidence_interval_95: [mean - margin, mean + margin],
    })
}

fn percentile(sorted: &[f64], percentile: f64) -> f64 {
    let rank = (percentile * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_nearest_rank_percentiles_and_confidence_interval() {
        let summary = summarize(&[1.0, 2.0, 3.0, 4.0, 100.0]).expect("summary");
        assert_eq!(summary.p50, 3.0);
        assert_eq!(summary.p95, 100.0);
        assert_eq!(summary.minimum, 1.0);
        assert!(summary.confidence_interval_95[0] < summary.mean);
        assert!(summary.confidence_interval_95[1] > summary.mean);
    }

    #[test]
    fn rejects_empty_and_non_finite_samples() {
        assert!(summarize(&[]).is_none());
        assert!(summarize(&[f64::NAN]).is_none());
    }
}
