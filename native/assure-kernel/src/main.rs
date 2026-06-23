use assure_kernel::{
    anytime_alarm, associate_sparse_2d, covariance_intersection_2d, custody_confidence,
    marginal_information_value, priority_score, schedule_tasks, update_evidence,
    update_log_evidence, CompositeTrack, Detection2, EvidenceChannel, PredictedTrack2,
    ReplayDecision, ReplayWindow, SensorSpec, TaskCandidate,
};
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;

#[derive(Serialize)]
struct ConformanceReport {
    custody: f64,
    priority: f64,
    information_value: assure_kernel::InformationValue,
    evidence_decision: &'static str,
    evidence_scores: Vec<f64>,
    track_frame_bytes: usize,
    track_round_trip: bool,
    tamper_rejected: bool,
    replay_rejected: bool,
    schedule_selected: usize,
    covariance_intersection_weight: f64,
    anytime_alarm: bool,
}

#[derive(Serialize)]
struct BenchmarkReport {
    iterations: usize,
    evidence_ns_per_operation: f64,
    custody_priority_ns_per_operation: f64,
    track_decode_ns_per_operation: f64,
    scheduler_ns_per_operation: f64,
    track_frame_bytes: usize,
    scheduler_candidates: usize,
    association_ns_per_operation: f64,
    association_objects: usize,
}

#[derive(Serialize)]
struct WireVector {
    key_hex: String,
    frame_hex: String,
    frame_bytes: usize,
    track: CompositeTrack,
}

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

fn conformance() -> ConformanceReport {
    let custody = custody_confidence(0.2, 0.1, 1, 0.95);
    let priority = priority_score(0.8, 0.7, 0.6, 0.3, custody);
    let information_value = marginal_information_value(0.5, 0.02, 1.0, 1.0, 0.05);
    let channels = [
        EvidenceChannel {
            weight: 1.0,
            slack: 0.5,
            flag_threshold: 2.0,
            reject_threshold: 5.0,
            decay: 0.9,
        },
        EvidenceChannel {
            weight: 1.2,
            slack: 0.25,
            flag_threshold: 1.5,
            reject_threshold: 4.0,
            decay: 0.8,
        },
    ];
    let evidence = update_evidence(&channels, &[1.0, 2.0], &[3.0, 3.0]).unwrap();
    let key = b"phase1-conformance-key";
    let track = sample_track();
    let frame = track.encode_authenticated(key).unwrap();
    let track_round_trip = CompositeTrack::decode_authenticated(&frame, key).as_ref() == Ok(&track);
    let mut tampered = frame;
    tampered[40] ^= 1;
    let tamper_rejected = CompositeTrack::decode_authenticated(&tampered, key).is_err();
    let mut replay_window = ReplayWindow::default();
    let first_sequence = replay_window.observe(track.sequence);
    let repeated_sequence = replay_window.observe(track.sequence);
    let sensors = vec![SensorSpec {
        name: "sensor".into(),
        frame_us: 1_000,
        maximum_duty_ppm: 600_000,
    }];
    let candidates = vec![
        TaskCandidate {
            sensor_index: 0,
            track_id: 1,
            cost_us: 200,
            deadline_us: 400,
            utility: 5.0,
            mode: 1,
        },
        TaskCandidate {
            sensor_index: 0,
            track_id: 2,
            cost_us: 200,
            deadline_us: 700,
            utility: 4.0,
            mode: 1,
        },
    ];
    let schedule = schedule_tasks(&sensors, &candidates, 8).unwrap();
    let fused = covariance_intersection_2d(
        [1.0, 0.0],
        [1.0, 0.0, 0.0, 4.0],
        [0.0, 1.0],
        [4.0, 0.0, 0.0, 1.0],
    )
    .unwrap();
    let mut log_evidence = 0.0;
    for _ in 0..10 {
        log_evidence = update_log_evidence(log_evidence, true, 0.02, 0.15).unwrap();
    }
    ConformanceReport {
        custody,
        priority,
        information_value,
        evidence_decision: evidence.decision,
        evidence_scores: evidence.scores,
        track_frame_bytes: frame.len(),
        track_round_trip,
        tamper_rejected,
        replay_rejected: first_sequence == ReplayDecision::Accept
            && repeated_sequence == ReplayDecision::Duplicate,
        schedule_selected: schedule.selected_indices.len(),
        covariance_intersection_weight: fused.weight,
        anytime_alarm: anytime_alarm(log_evidence, 0.01),
    }
}

fn elapsed_ns_per_operation(iterations: usize, mut operation: impl FnMut()) -> f64 {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    started.elapsed().as_nanos() as f64 / iterations as f64
}

fn encode_hex(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0F) as usize] as char);
    }
    output
}

fn wire_vector() -> WireVector {
    let key = b"phase1-conformance-key";
    let track = sample_track();
    let frame = track.encode_authenticated(key).unwrap();
    WireVector {
        key_hex: encode_hex(key),
        frame_hex: encode_hex(&frame),
        frame_bytes: frame.len(),
        track,
    }
}

fn benchmark(iterations: usize) -> BenchmarkReport {
    let channels = [
        EvidenceChannel {
            weight: 1.0,
            slack: 0.5,
            flag_threshold: 2.0,
            reject_threshold: 5.0,
            decay: 0.9,
        },
        EvidenceChannel {
            weight: 1.2,
            slack: 0.25,
            flag_threshold: 1.5,
            reject_threshold: 4.0,
            decay: 0.8,
        },
        EvidenceChannel {
            weight: 0.9,
            slack: 0.4,
            flag_threshold: 2.5,
            reject_threshold: 5.5,
            decay: 0.92,
        },
    ];
    let evidence_ns_per_operation = elapsed_ns_per_operation(iterations, || {
        black_box(update_evidence(
            black_box(&channels),
            black_box(&[1.0, 2.0, 0.5]),
            black_box(&[3.0, 3.0, 2.0]),
        ))
        .unwrap();
    });
    let custody_priority_ns_per_operation = elapsed_ns_per_operation(iterations, || {
        let custody = custody_confidence(
            black_box(0.2),
            black_box(0.1),
            black_box(1),
            black_box(0.95),
        );
        black_box(priority_score(0.8, 0.7, 0.6, 0.3, custody));
    });
    let key = b"phase1-benchmark-key";
    let frame = sample_track().encode_authenticated(key).unwrap();
    let track_decode_ns_per_operation = elapsed_ns_per_operation(iterations, || {
        black_box(CompositeTrack::decode_authenticated(
            black_box(&frame),
            black_box(key),
        ))
        .unwrap();
    });

    let sensors: Vec<SensorSpec> = (0..4)
        .map(|index| SensorSpec {
            name: format!("sensor-{index}"),
            frame_us: 1_000_000,
            maximum_duty_ppm: 650_000,
        })
        .collect();
    let candidates: Vec<TaskCandidate> = (0..240)
        .map(|index| TaskCandidate {
            sensor_index: index % sensors.len(),
            track_id: index as u32,
            cost_us: 1_000 + (index % 17) as u64 * 100,
            deadline_us: 100_000 + (index % 8) as u64 * 50_000,
            utility: 1.0 + (index % 31) as f64 / 10.0,
            mode: u8::from(index % 3 == 0),
        })
        .collect();
    let scheduler_iterations = (iterations / 100).max(100);
    let scheduler_ns_per_operation = elapsed_ns_per_operation(scheduler_iterations, || {
        black_box(schedule_tasks(
            black_box(&sensors),
            black_box(&candidates),
            4_096,
        ))
        .unwrap();
    });
    let association_objects = 1_000;
    let tracks: Vec<PredictedTrack2> = (0..association_objects)
        .map(|index| PredictedTrack2 {
            track_id: index as u64,
            position: [(index % 50) as f64 * 25.0, (index / 50) as f64 * 25.0],
            velocity: [1.0 + (index % 7) as f64 * 0.02, 0.2],
        })
        .collect();
    let detections: Vec<Detection2> = tracks
        .iter()
        .enumerate()
        .rev()
        .map(|(index, track)| Detection2 {
            detection_id: index as u64,
            position: [track.position[0] + 0.3, track.position[1] - 0.2],
            velocity: track.velocity,
        })
        .collect();
    let association_iterations = (iterations / 2_000).max(20);
    let association_ns_per_operation = elapsed_ns_per_operation(association_iterations, || {
        black_box(associate_sparse_2d(
            black_box(&tracks),
            black_box(&detections),
            3.0,
            1.0,
            10_000,
        ))
        .unwrap();
    });

    BenchmarkReport {
        iterations,
        evidence_ns_per_operation,
        custody_priority_ns_per_operation,
        track_decode_ns_per_operation,
        scheduler_ns_per_operation,
        track_frame_bytes: frame.len(),
        scheduler_candidates: candidates.len(),
        association_ns_per_operation,
        association_objects,
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let command = arguments
        .get(1)
        .map(String::as_str)
        .unwrap_or("conformance");
    let output = match command {
        "conformance" => serde_json::to_string_pretty(&conformance()).unwrap(),
        "benchmark" => {
            let iterations = arguments
                .get(2)
                .and_then(|value| value.parse().ok())
                .unwrap_or(250_000);
            serde_json::to_string_pretty(&benchmark(iterations)).unwrap()
        }
        "vector" => serde_json::to_string_pretty(&wire_vector()).unwrap(),
        _ => {
            eprintln!("usage: assure-kernel [conformance|benchmark [iterations]|vector]");
            std::process::exit(2);
        }
    };
    println!("{output}");
}
