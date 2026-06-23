#include "assure_kernel.h"

#include <math.h>
#include <stdio.h>

int main(void) {
    const double custody = assure_custody_confidence(0.2, 0.1, 1, 0.95);
    const double priority = assure_priority_score(0.8, 0.7, 0.6, 0.3, custody);
    const double utility =
        assure_information_utility(0.5, 0.02, 1.0, 1.0, 0.05);
    if (!isfinite(custody) || !isfinite(priority) || !isfinite(utility)) {
        return 2;
    }
    if (custody <= 0.0 || custody > 1.0 || priority <= 0.0 ||
        priority > 1.0 || utility <= 0.0) {
        return 3;
    }
    printf("custody=%.9f priority=%.9f utility=%.9f\n", custody, priority,
           utility);
    return 0;
}
