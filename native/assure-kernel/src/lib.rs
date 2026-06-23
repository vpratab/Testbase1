//! Small, deterministic kernels for mission assurance decisions.
//!
//! The Python code remains the research and evaluation layer. This crate defines
//! the bounded native execution path intended for representative hardware tests.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

pub const TRACK_VERSION: u16 = 1;
pub const TRACK_BODY_LEN: usize = 104;
pub const TRACK_FRAME_LEN: usize = TRACK_BODY_LEN + 32;
pub const MAX_TASK_CANDIDATES: usize = 4_096;
const TRACK_MAGIC: &[u8; 4] = b"ATK1";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EvidenceChannel {
    pub weight: f64,
    pub slack: f64,
    pub flag_threshold: f64,
    pub reject_threshold: f64,
    pub decay: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceResult {
    pub decision: &'static str,
    pub scores: Vec<f64>,
    pub weighted_total: f64,
    pub flagged_channels: Vec<usize>,
    pub rejected_channels: Vec<usize>,
}

pub fn update_evidence(
    channels: &[EvidenceChannel],
    previous_scores: &[f64],
    evidence: &[f64],
) -> Result<EvidenceResult, &'static str> {
    if channels.len() != previous_scores.len() || channels.len() != evidence.len() {
        return Err("evidence vector lengths must match");
    }
    if channels.len() > 64 {
        return Err("at most 64 evidence channels are supported");
    }

    let mut scores = Vec::with_capacity(channels.len());
    let mut flagged_channels = Vec::new();
    let mut rejected_channels = Vec::new();
    let mut weighted_total = 0.0;

    for (index, ((channel, previous), value)) in channels
        .iter()
        .zip(previous_scores)
        .zip(evidence)
        .enumerate()
    {
        if !channel.weight.is_finite()
            || !channel.slack.is_finite()
            || !channel.flag_threshold.is_finite()
            || !channel.reject_threshold.is_finite()
            || !channel.decay.is_finite()
            || !previous.is_finite()
            || !value.is_finite()
        {
            return Err("evidence inputs must be finite");
        }
        let score = (previous * channel.decay + value.max(0.0) - channel.slack).max(0.0);
        weighted_total += score * channel.weight;
        if score >= channel.reject_threshold {
            rejected_channels.push(index);
        } else if score >= channel.flag_threshold {
            flagged_channels.push(index);
        }
        scores.push(score);
    }

    let decision = if !rejected_channels.is_empty() {
        "reject"
    } else if !flagged_channels.is_empty() {
        "flag"
    } else {
        "accept"
    };
    Ok(EvidenceResult {
        decision,
        scores,
        weighted_total,
        flagged_channels,
        rejected_channels,
    })
}

pub fn custody_confidence(
    association_distance: f64,
    velocity_difference: f64,
    misses: u32,
    identity_consistency: f64,
) -> f64 {
    let penalty =
        0.08 * association_distance + 0.18 * velocity_difference + 0.12 * f64::from(misses);
    (identity_consistency * (-penalty).exp()).clamp(0.0, 1.0)
}

pub fn priority_score(
    anomaly: f64,
    forecasted_proximity: f64,
    closing_rate: f64,
    uncertainty: f64,
    custody: f64,
) -> f64 {
    let raw = 0.38 * anomaly
        + 0.24 * forecasted_proximity
        + 0.18 * closing_rate
        + 0.12 * uncertainty
        + 0.08 * custody;
    (raw * (0.55 + 0.45 * custody)).clamp(0.0, 1.0)
}

/// Stable C ABI for integration into existing C/C++ combat-system processes.
#[no_mangle]
pub extern "C" fn assure_custody_confidence(
    association_distance: f64,
    velocity_difference: f64,
    misses: u32,
    identity_consistency: f64,
) -> f64 {
    custody_confidence(
        association_distance,
        velocity_difference,
        misses,
        identity_consistency,
    )
}

/// Stable C ABI for integration into existing C/C++ combat-system processes.
#[no_mangle]
pub extern "C" fn assure_priority_score(
    anomaly: f64,
    forecasted_proximity: f64,
    closing_rate: f64,
    uncertainty: f64,
    custody: f64,
) -> f64 {
    priority_score(
        anomaly,
        forecasted_proximity,
        closing_rate,
        uncertainty,
        custody,
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct InformationValue {
    pub posterior_variance: f64,
    pub information_gain: f64,
    pub utility: f64,
}

pub fn marginal_information_value(
    prior_variance: f64,
    measurement_variance: f64,
    mission_priority: f64,
    task_cost: f64,
    conflict_penalty: f64,
) -> InformationValue {
    let posterior_variance =
        1.0 / (1.0 / prior_variance.max(1.0e-12) + 1.0 / measurement_variance.max(1.0e-12));
    let information_gain = (prior_variance - posterior_variance).max(0.0);
    let utility = information_gain * mission_priority.max(0.0) / task_cost.max(1.0e-12)
        - conflict_penalty.max(0.0);
    InformationValue {
        posterior_variance,
        information_gain,
        utility,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct FusedEstimate2 {
    pub state: [f64; 2],
    pub covariance: [f64; 4],
    pub weight: f64,
}

fn inverse_2x2(matrix: [f64; 4]) -> Option<[f64; 4]> {
    let determinant = matrix[0] * matrix[3] - matrix[1] * matrix[2];
    if !determinant.is_finite() || determinant <= 1.0e-15 {
        return None;
    }
    Some([
        matrix[3] / determinant,
        -matrix[1] / determinant,
        -matrix[2] / determinant,
        matrix[0] / determinant,
    ])
}

fn matrix_vector_2x2(matrix: [f64; 4], vector: [f64; 2]) -> [f64; 2] {
    [
        matrix[0] * vector[0] + matrix[1] * vector[1],
        matrix[2] * vector[0] + matrix[3] * vector[1],
    ]
}

/// Conservative two-dimensional fusion when cross-correlation is unknown.
pub fn covariance_intersection_2d(
    state_a: [f64; 2],
    covariance_a: [f64; 4],
    state_b: [f64; 2],
    covariance_b: [f64; 4],
) -> Result<FusedEstimate2, &'static str> {
    if !state_a
        .iter()
        .chain(covariance_a.iter())
        .chain(state_b.iter())
        .chain(covariance_b.iter())
        .all(|value| value.is_finite())
    {
        return Err("fusion inputs must be finite");
    }
    let inverse_a = inverse_2x2(covariance_a).ok_or("covariance A is not positive definite")?;
    let inverse_b = inverse_2x2(covariance_b).ok_or("covariance B is not positive definite")?;
    let mut best: Option<(f64, FusedEstimate2)> = None;
    for step in 0..=100 {
        let weight = f64::from(step) / 100.0;
        let information = [
            weight * inverse_a[0] + (1.0 - weight) * inverse_b[0],
            weight * inverse_a[1] + (1.0 - weight) * inverse_b[1],
            weight * inverse_a[2] + (1.0 - weight) * inverse_b[2],
            weight * inverse_a[3] + (1.0 - weight) * inverse_b[3],
        ];
        let covariance =
            inverse_2x2(information).ok_or("fused covariance is not positive definite")?;
        let information_state_a = matrix_vector_2x2(inverse_a, state_a);
        let information_state_b = matrix_vector_2x2(inverse_b, state_b);
        let combined = [
            weight * information_state_a[0] + (1.0 - weight) * information_state_b[0],
            weight * information_state_a[1] + (1.0 - weight) * information_state_b[1],
        ];
        let state = matrix_vector_2x2(covariance, combined);
        let determinant = covariance[0] * covariance[3] - covariance[1] * covariance[2];
        let candidate = FusedEstimate2 {
            state,
            covariance,
            weight,
        };
        if match &best {
            None => true,
            Some((objective, _)) => determinant < *objective,
        } {
            best = Some((determinant, candidate));
        }
    }
    Ok(best.expect("weight grid is non-empty").1)
}

/// Log e-process update for a Bernoulli nominal-vs-attack model.
pub fn update_log_evidence(
    current_log_evidence: f64,
    event: bool,
    nominal_rate: f64,
    attack_rate: f64,
) -> Result<f64, &'static str> {
    if !current_log_evidence.is_finite()
        || !(0.0..1.0).contains(&nominal_rate)
        || !(0.0..1.0).contains(&attack_rate)
    {
        return Err("rates must be finite probabilities strictly between zero and one");
    }
    let increment = if event {
        (attack_rate / nominal_rate).ln()
    } else {
        ((1.0 - attack_rate) / (1.0 - nominal_rate)).ln()
    };
    Ok(current_log_evidence + increment)
}

pub fn anytime_alarm(log_evidence: f64, alpha: f64) -> bool {
    log_evidence.is_finite() && (0.0..1.0).contains(&alpha) && log_evidence >= (1.0 / alpha).ln()
}

/// Return conflict-adjusted information utility through a stable C ABI.
#[no_mangle]
pub extern "C" fn assure_information_utility(
    prior_variance: f64,
    measurement_variance: f64,
    mission_priority: f64,
    task_cost: f64,
    conflict_penalty: f64,
) -> f64 {
    marginal_information_value(
        prior_variance,
        measurement_variance,
        mission_priority,
        task_cost,
        conflict_penalty,
    )
    .utility
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CompositeTrack {
    pub flags: u16,
    pub sequence: u64,
    pub track_id: u64,
    pub source: u8,
    pub classification: u8,
    pub timestamp_ns: u64,
    pub position: [f64; 3],
    pub velocity: [f32; 3],
    pub covariance_upper: [f32; 6],
    pub quality: f32,
    pub anomaly: f32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PredictedTrack2 {
    pub track_id: u64,
    pub position: [f64; 2],
    pub velocity: [f64; 2],
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Detection2 {
    pub detection_id: u64,
    pub position: [f64; 2],
    pub velocity: [f64; 2],
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct AssociationPair {
    pub track_index: usize,
    pub detection_index: usize,
    pub cost: f64,
}

/// Sparse gated assignment using spatial bins and globally sorted candidate
/// edges. This avoids materializing a dense N x M cost matrix.
pub fn associate_sparse_2d(
    tracks: &[PredictedTrack2],
    detections: &[Detection2],
    position_gate: f64,
    velocity_weight: f64,
    maximum_edges: usize,
) -> Result<Vec<AssociationPair>, &'static str> {
    if !position_gate.is_finite() || position_gate <= 0.0 {
        return Err("position gate must be finite and positive");
    }
    if !velocity_weight.is_finite() || velocity_weight < 0.0 {
        return Err("velocity weight must be finite and nonnegative");
    }
    if maximum_edges == 0 || maximum_edges > 1_000_000 {
        return Err("maximum edge count is outside the supported bound");
    }
    if tracks
        .iter()
        .flat_map(|track| track.position.iter().chain(track.velocity.iter()))
        .chain(
            detections
                .iter()
                .flat_map(|item| item.position.iter().chain(item.velocity.iter())),
        )
        .any(|value| !value.is_finite())
    {
        return Err("association inputs must be finite");
    }

    let cell = position_gate;
    let mut bins: BTreeMap<(i64, i64), Vec<usize>> = BTreeMap::new();
    for (index, detection) in detections.iter().enumerate() {
        let key = (
            (detection.position[0] / cell).floor() as i64,
            (detection.position[1] / cell).floor() as i64,
        );
        bins.entry(key).or_default().push(index);
    }

    let gate_squared = position_gate * position_gate;
    let mut edges = Vec::new();
    for (track_index, track) in tracks.iter().enumerate() {
        let base = (
            (track.position[0] / cell).floor() as i64,
            (track.position[1] / cell).floor() as i64,
        );
        for dx in -1..=1 {
            for dy in -1..=1 {
                if let Some(indices) = bins.get(&(base.0 + dx, base.1 + dy)) {
                    for detection_index in indices {
                        let detection = detections[*detection_index];
                        let px = detection.position[0] - track.position[0];
                        let py = detection.position[1] - track.position[1];
                        let position_distance_squared = px * px + py * py;
                        if position_distance_squared > gate_squared {
                            continue;
                        }
                        let vx = detection.velocity[0] - track.velocity[0];
                        let vy = detection.velocity[1] - track.velocity[1];
                        let cost =
                            position_distance_squared + velocity_weight * (vx * vx + vy * vy);
                        edges.push(AssociationPair {
                            track_index,
                            detection_index: *detection_index,
                            cost,
                        });
                        if edges.len() > maximum_edges {
                            return Err("association edge bound exceeded");
                        }
                    }
                }
            }
        }
    }
    edges.sort_unstable_by(|left, right| {
        left.cost
            .partial_cmp(&right.cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.track_index.cmp(&right.track_index))
            .then_with(|| left.detection_index.cmp(&right.detection_index))
    });

    let mut track_used = vec![false; tracks.len()];
    let mut detection_used = vec![false; detections.len()];
    let mut selected = Vec::with_capacity(tracks.len().min(detections.len()));
    for edge in edges {
        if track_used[edge.track_index] || detection_used[edge.detection_index] {
            continue;
        }
        track_used[edge.track_index] = true;
        detection_used[edge.detection_index] = true;
        selected.push(edge);
    }
    selected.sort_unstable_by_key(|pair| pair.track_index);
    Ok(selected)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrackError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    AuthenticationFailed,
    InvalidSource,
    NonFiniteValue,
    InvalidProbability,
    NegativeCovariance,
}

impl fmt::Display for TrackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TrackError {}

impl CompositeTrack {
    pub fn validate(&self) -> Result<(), TrackError> {
        if !(1..=3).contains(&self.source) {
            return Err(TrackError::InvalidSource);
        }
        if !self.position.iter().all(|value| value.is_finite())
            || !self.velocity.iter().all(|value| value.is_finite())
            || !self.covariance_upper.iter().all(|value| value.is_finite())
            || !self.quality.is_finite()
            || !self.anomaly.is_finite()
        {
            return Err(TrackError::NonFiniteValue);
        }
        if !(0.0..=1.0).contains(&self.quality) || !(0.0..=1.0).contains(&self.anomaly) {
            return Err(TrackError::InvalidProbability);
        }
        if self.covariance_upper.iter().any(|value| *value < 0.0) {
            return Err(TrackError::NegativeCovariance);
        }
        Ok(())
    }

    pub fn encode_authenticated(&self, key: &[u8]) -> Result<[u8; TRACK_FRAME_LEN], TrackError> {
        self.validate()?;
        let mut frame = [0_u8; TRACK_FRAME_LEN];
        let mut offset = 0;
        put(&mut frame, &mut offset, TRACK_MAGIC);
        put(&mut frame, &mut offset, &TRACK_VERSION.to_be_bytes());
        put(&mut frame, &mut offset, &self.flags.to_be_bytes());
        put(&mut frame, &mut offset, &self.sequence.to_be_bytes());
        put(&mut frame, &mut offset, &self.track_id.to_be_bytes());
        frame[offset] = self.source;
        offset += 1;
        frame[offset] = self.classification;
        offset += 1;
        put(&mut frame, &mut offset, &[0, 0]);
        put(&mut frame, &mut offset, &self.timestamp_ns.to_be_bytes());
        for value in self.position {
            put(&mut frame, &mut offset, &value.to_bits().to_be_bytes());
        }
        for value in self.velocity {
            put(&mut frame, &mut offset, &value.to_bits().to_be_bytes());
        }
        for value in self.covariance_upper {
            put(&mut frame, &mut offset, &value.to_bits().to_be_bytes());
        }
        put(
            &mut frame,
            &mut offset,
            &self.quality.to_bits().to_be_bytes(),
        );
        put(
            &mut frame,
            &mut offset,
            &self.anomaly.to_bits().to_be_bytes(),
        );
        debug_assert_eq!(offset, TRACK_BODY_LEN);

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
        mac.update(&frame[..TRACK_BODY_LEN]);
        frame[TRACK_BODY_LEN..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(frame)
    }

    pub fn decode_authenticated(frame: &[u8], key: &[u8]) -> Result<Self, TrackError> {
        if frame.len() != TRACK_FRAME_LEN {
            return Err(TrackError::InvalidLength);
        }
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
        mac.update(&frame[..TRACK_BODY_LEN]);
        mac.verify_slice(&frame[TRACK_BODY_LEN..])
            .map_err(|_| TrackError::AuthenticationFailed)?;

        let mut offset = 0;
        if take::<4>(frame, &mut offset) != *TRACK_MAGIC {
            return Err(TrackError::InvalidMagic);
        }
        if u16::from_be_bytes(take(frame, &mut offset)) != TRACK_VERSION {
            return Err(TrackError::UnsupportedVersion);
        }
        let flags = u16::from_be_bytes(take(frame, &mut offset));
        let sequence = u64::from_be_bytes(take(frame, &mut offset));
        let track_id = u64::from_be_bytes(take(frame, &mut offset));
        let source = frame[offset];
        offset += 1;
        let classification = frame[offset];
        offset += 1;
        offset += 2;
        let timestamp_ns = u64::from_be_bytes(take(frame, &mut offset));
        let mut position = [0.0; 3];
        for value in &mut position {
            *value = f64::from_bits(u64::from_be_bytes(take(frame, &mut offset)));
        }
        let mut velocity = [0.0; 3];
        for value in &mut velocity {
            *value = f32::from_bits(u32::from_be_bytes(take(frame, &mut offset)));
        }
        let mut covariance_upper = [0.0; 6];
        for value in &mut covariance_upper {
            *value = f32::from_bits(u32::from_be_bytes(take(frame, &mut offset)));
        }
        let quality = f32::from_bits(u32::from_be_bytes(take(frame, &mut offset)));
        let anomaly = f32::from_bits(u32::from_be_bytes(take(frame, &mut offset)));
        debug_assert_eq!(offset, TRACK_BODY_LEN);

        let result = Self {
            flags,
            sequence,
            track_id,
            source,
            classification,
            timestamp_ns,
            position,
            velocity,
            covariance_upper,
            quality,
            anomaly,
        };
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayDecision {
    Accept,
    Duplicate,
    TooOld,
}

/// Constant-memory 64-message anti-replay window for one authenticated stream.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplayWindow {
    initialized: bool,
    highest_sequence: u64,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn observe(&mut self, sequence: u64) -> ReplayDecision {
        if !self.initialized {
            self.initialized = true;
            self.highest_sequence = sequence;
            self.bitmap = 1;
            return ReplayDecision::Accept;
        }
        if sequence > self.highest_sequence {
            let distance = sequence - self.highest_sequence;
            self.bitmap = if distance >= 64 {
                1
            } else {
                (self.bitmap << distance) | 1
            };
            self.highest_sequence = sequence;
            return ReplayDecision::Accept;
        }

        let distance = self.highest_sequence - sequence;
        if distance >= 64 {
            return ReplayDecision::TooOld;
        }
        let mask = 1_u64 << distance;
        if self.bitmap & mask != 0 {
            ReplayDecision::Duplicate
        } else {
            self.bitmap |= mask;
            ReplayDecision::Accept
        }
    }
}

fn put<const N: usize>(buffer: &mut [u8], offset: &mut usize, value: &[u8; N]) {
    buffer[*offset..*offset + N].copy_from_slice(value);
    *offset += N;
}

fn take<const N: usize>(buffer: &[u8], offset: &mut usize) -> [u8; N] {
    let mut value = [0_u8; N];
    value.copy_from_slice(&buffer[*offset..*offset + N]);
    *offset += N;
    value
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SensorSpec {
    pub name: String,
    pub frame_us: u64,
    pub maximum_duty_ppm: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TaskCandidate {
    pub sensor_index: usize,
    pub track_id: u32,
    pub cost_us: u64,
    pub deadline_us: u64,
    pub utility: f64,
    pub mode: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScheduleResult {
    pub selected_indices: Vec<usize>,
    pub used_us: Vec<u64>,
    pub rejected_for_budget: usize,
    pub rejected_for_deadline: usize,
}

pub fn schedule_tasks(
    sensors: &[SensorSpec],
    candidates: &[TaskCandidate],
    maximum_candidates: usize,
) -> Result<ScheduleResult, &'static str> {
    if sensors.is_empty() || sensors.len() > 64 {
        return Err("sensor count must be between 1 and 64");
    }
    if maximum_candidates > MAX_TASK_CANDIDATES {
        return Err("configured candidate bound exceeds hard limit");
    }
    if candidates.len() > maximum_candidates {
        return Err("candidate bound exceeded");
    }
    if candidates.iter().any(|candidate| {
        candidate.sensor_index >= sensors.len()
            || !candidate.utility.is_finite()
            || candidate.cost_us == 0
    }) {
        return Err("invalid task candidate");
    }

    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_unstable_by(|left, right| {
        let a = &candidates[*left];
        let b = &candidates[*right];
        a.deadline_us
            .cmp(&b.deadline_us)
            .then_with(|| b.utility.partial_cmp(&a.utility).unwrap_or(Ordering::Equal))
            .then_with(|| a.sensor_index.cmp(&b.sensor_index))
            .then_with(|| a.track_id.cmp(&b.track_id))
    });

    let budgets: Vec<u64> = sensors
        .iter()
        .map(|sensor| {
            sensor
                .frame_us
                .saturating_mul(u64::from(sensor.maximum_duty_ppm))
                / 1_000_000
        })
        .collect();
    let mut used_us = vec![0_u64; sensors.len()];
    let mut selected_indices = Vec::with_capacity(candidates.len());
    let mut rejected_for_budget = 0;
    let mut rejected_for_deadline = 0;

    for index in order {
        let candidate = &candidates[index];
        let finish = used_us[candidate.sensor_index].saturating_add(candidate.cost_us);
        if finish > budgets[candidate.sensor_index] {
            rejected_for_budget += 1;
            continue;
        }
        if finish > candidate.deadline_us {
            rejected_for_deadline += 1;
            continue;
        }
        used_us[candidate.sensor_index] = finish;
        selected_indices.push(index);
    }

    Ok(ScheduleResult {
        selected_indices,
        used_us,
        rejected_for_budget,
        rejected_for_deadline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_track() -> CompositeTrack {
        CompositeTrack {
            flags: 3,
            sequence: 42,
            track_id: 17,
            source: 1,
            classification: 2,
            timestamp_ns: 123_456,
            position: [47.1, -122.3, 12.0],
            velocity: [2.0, 3.0, 0.5],
            covariance_upper: [1.0, 0.1, 0.1, 2.0, 0.2, 3.0],
            quality: 0.9,
            anomaly: 0.2,
        }
    }

    #[test]
    fn evidence_accumulates_and_rejects() {
        let channels = [EvidenceChannel {
            weight: 1.0,
            slack: 0.5,
            flag_threshold: 2.0,
            reject_threshold: 4.0,
            decay: 0.9,
        }];
        let mut scores = vec![0.0];
        let mut result = update_evidence(&channels, &scores, &[2.0]).unwrap();
        scores = result.scores.clone();
        result = update_evidence(&channels, &scores, &[4.0]).unwrap();
        assert_eq!(result.decision, "reject");
    }

    #[test]
    fn track_round_trip_and_tamper_rejection() {
        let key = b"phase1-conformance-key";
        let expected = sample_track();
        let frame = expected.encode_authenticated(key).unwrap();
        assert_eq!(
            CompositeTrack::decode_authenticated(&frame, key).unwrap(),
            expected
        );
        let mut tampered = frame;
        tampered[40] ^= 1;
        assert_eq!(
            CompositeTrack::decode_authenticated(&tampered, key),
            Err(TrackError::AuthenticationFailed)
        );
    }

    #[test]
    fn scheduler_enforces_bounds_and_budget() {
        let sensors = vec![SensorSpec {
            name: "sensor".into(),
            frame_us: 1_000,
            maximum_duty_ppm: 500_000,
        }];
        let candidates = vec![
            TaskCandidate {
                sensor_index: 0,
                track_id: 1,
                cost_us: 300,
                deadline_us: 500,
                utility: 5.0,
                mode: 1,
            },
            TaskCandidate {
                sensor_index: 0,
                track_id: 2,
                cost_us: 300,
                deadline_us: 1_000,
                utility: 4.0,
                mode: 1,
            },
        ];
        let result = schedule_tasks(&sensors, &candidates, 8).unwrap();
        assert_eq!(result.selected_indices, vec![0]);
        assert_eq!(result.rejected_for_budget, 1);
        assert!(schedule_tasks(&sensors, &candidates, 1).is_err());
        assert!(schedule_tasks(&sensors, &candidates, MAX_TASK_CANDIDATES + 1).is_err());
    }

    #[test]
    fn replay_window_accepts_reordering_and_rejects_replay() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.observe(100), ReplayDecision::Accept);
        assert_eq!(window.observe(102), ReplayDecision::Accept);
        assert_eq!(window.observe(101), ReplayDecision::Accept);
        assert_eq!(window.observe(101), ReplayDecision::Duplicate);
        assert_eq!(window.observe(20), ReplayDecision::TooOld);
    }

    #[test]
    fn sparse_association_preserves_identity_without_dense_matrix() {
        let tracks: Vec<PredictedTrack2> = (0..200)
            .map(|index| PredictedTrack2 {
                track_id: index,
                position: [index as f64 * 10.0, (index % 7) as f64 * 12.0],
                velocity: [1.0, 0.2],
            })
            .collect();
        let detections: Vec<Detection2> = tracks
            .iter()
            .enumerate()
            .rev()
            .map(|(index, track)| Detection2 {
                detection_id: index as u64,
                position: [track.position[0] + 0.2, track.position[1] - 0.1],
                velocity: track.velocity,
            })
            .collect();
        let pairs = associate_sparse_2d(&tracks, &detections, 2.0, 1.0, 1_000).unwrap();
        assert_eq!(pairs.len(), tracks.len());
        for pair in pairs {
            assert_eq!(
                tracks[pair.track_index].track_id,
                detections[pair.detection_index].detection_id
            );
        }
    }

    #[test]
    fn malformed_authenticated_frames_never_decode() {
        let key = b"malformed-frame-test";
        for length in 0..TRACK_FRAME_LEN {
            let input = vec![0xA5; length];
            assert!(CompositeTrack::decode_authenticated(&input, key).is_err());
        }
        let valid = sample_track().encode_authenticated(key).unwrap();
        for index in 0..TRACK_BODY_LEN {
            let mut modified = valid;
            modified[index] ^= 1;
            assert_eq!(
                CompositeTrack::decode_authenticated(&modified, key),
                Err(TrackError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn c_abi_matches_native_functions() {
        let custody = custody_confidence(0.2, 0.1, 1, 0.95);
        assert_eq!(assure_custody_confidence(0.2, 0.1, 1, 0.95), custody);
        assert_eq!(
            assure_priority_score(0.8, 0.7, 0.6, 0.3, custody),
            priority_score(0.8, 0.7, 0.6, 0.3, custody)
        );
        assert_eq!(
            assure_information_utility(0.5, 0.02, 1.0, 1.0, 0.05),
            marginal_information_value(0.5, 0.02, 1.0, 1.0, 0.05).utility
        );
    }

    #[test]
    fn covariance_intersection_is_conservative_and_symmetric() {
        let result = covariance_intersection_2d(
            [1.0, 0.0],
            [1.0, 0.0, 0.0, 4.0],
            [0.0, 1.0],
            [4.0, 0.0, 0.0, 1.0],
        )
        .unwrap();
        assert!((result.weight - 0.5).abs() <= 0.01);
        assert!(result.covariance[0] > 1.0);
        assert!(result.covariance[3] > 1.0);
    }

    #[test]
    fn anytime_evidence_accumulates_persistent_events() {
        let mut evidence = 0.0;
        for _ in 0..10 {
            evidence = update_log_evidence(evidence, true, 0.02, 0.15).unwrap();
        }
        assert!(anytime_alarm(evidence, 0.01));
        assert!(!anytime_alarm(0.0, 0.01));
    }
}
