#ifndef ASSURE_KERNEL_H
#define ASSURE_KERNEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

double assure_custody_confidence(
    double association_distance,
    double velocity_difference,
    uint32_t misses,
    double identity_consistency);

double assure_priority_score(
    double anomaly,
    double forecasted_proximity,
    double closing_rate,
    double uncertainty,
    double custody);

double assure_information_utility(
    double prior_variance,
    double measurement_variance,
    double mission_priority,
    double task_cost,
    double conflict_penalty);

#ifdef __cplusplus
}
#endif

#endif
