use crate::error::ProxyError;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed { consecutive_failures: u32 },
    Open { opened_at: Instant },
    HalfOpen { probe_in_flight: bool },
}

impl CircuitState {
    pub fn name(&self) -> &'static str {
        match self {
            CircuitState::Closed { .. } => "CLOSED",
            CircuitState::Open { .. } => "OPEN",
            CircuitState::HalfOpen { .. } => "HALF-OPEN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown_duration: Duration,
    state: Arc<Mutex<CircuitState>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cooldown_duration: Duration) -> Self {
        Self {
            failure_threshold,
            cooldown_duration,
            state: Arc::new(Mutex::new(CircuitState::Closed {
                consecutive_failures: 0,
            })),
        }
    }

    pub fn state_name(&self) -> String {
        self.state.lock().name().to_string()
    }

    /// Evaluates whether the request is allowed to proceed to upstream.
    pub fn check_allow(&self) -> Result<(), ProxyError> {
        let mut lock = self.state.lock();
        match *lock {
            CircuitState::Closed { .. } => Ok(()),
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= self.cooldown_duration {
                    tracing::info!(
                        "Circuit Breaker cooldown elapsed. Transitioning from OPEN to HALF-OPEN."
                    );
                    *lock = CircuitState::HalfOpen {
                        probe_in_flight: true,
                    };
                    Ok(())
                } else {
                    Err(ProxyError::Upstream(
                        "Circuit breaker is OPEN (upstream cooling down). Request rejected fast."
                            .to_string(),
                    ))
                }
            }
            CircuitState::HalfOpen { probe_in_flight } => {
                if !probe_in_flight {
                    *lock = CircuitState::HalfOpen {
                        probe_in_flight: true,
                    };
                    Ok(())
                } else {
                    Err(ProxyError::Upstream(
                        "Circuit breaker is HALF-OPEN (probe request already in flight). Request rejected fast."
                            .to_string(),
                    ))
                }
            }
        }
    }

    /// Records the outcome of an upstream request attempt.
    pub fn record_result(&self, is_success: bool) {
        let mut lock = self.state.lock();
        match *lock {
            CircuitState::Closed {
                mut consecutive_failures,
            } => {
                if is_success {
                    if consecutive_failures > 0 {
                        *lock = CircuitState::Closed {
                            consecutive_failures: 0,
                        };
                    }
                } else {
                    consecutive_failures += 1;
                    if consecutive_failures >= self.failure_threshold {
                        tracing::warn!(
                            "Circuit Breaker failure threshold ({}) reached. Transitioning to OPEN.",
                            self.failure_threshold
                        );
                        *lock = CircuitState::Open {
                            opened_at: Instant::now(),
                        };
                    } else {
                        *lock = CircuitState::Closed {
                            consecutive_failures,
                        };
                    }
                }
            }
            CircuitState::HalfOpen { .. } => {
                if is_success {
                    tracing::info!(
                        "Circuit Breaker HALF-OPEN probe succeeded. Transitioning to CLOSED."
                    );
                    *lock = CircuitState::Closed {
                        consecutive_failures: 0,
                    };
                } else {
                    tracing::warn!(
                        "Circuit Breaker HALF-OPEN probe failed. Transitioning back to OPEN."
                    );
                    *lock = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                }
            }
            CircuitState::Open { .. } => {
                if is_success {
                    *lock = CircuitState::Closed {
                        consecutive_failures: 0,
                    };
                }
            }
        }
    }
}
