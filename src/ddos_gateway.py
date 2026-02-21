"""AI-driven DDoS mitigation gateway prototype.

The gateway combines:
- Per-IP token-bucket rate limiting.
- Global traffic anomaly detection with an adaptive EWMA baseline.
- A lightweight risk score to decide allow/challenge/block.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import exp


@dataclass
class TokenBucket:
    capacity: float
    refill_rate: float
    tokens: float = field(init=False)
    last_seen: float = field(default=0.0)

    def __post_init__(self) -> None:
        self.tokens = self.capacity

    def consume(self, now: float, amount: float = 1.0) -> bool:
        elapsed = max(0.0, now - self.last_seen)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_seen = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


@dataclass
class TrafficStats:
    alpha: float = 0.2
    ewma_rps: float = 0.0
    ewma_dev: float = 1.0
    current_second: int = 0
    current_count: int = 0

    def update(self, now: float) -> tuple[float, float]:
        sec = int(now)
        if sec == self.current_second:
            self.current_count += 1
            return self.ewma_rps, 0.0

        observed_rps = float(self.current_count)
        prev = self.ewma_rps
        self.ewma_rps = self.alpha * observed_rps + (1 - self.alpha) * self.ewma_rps
        dev_obs = abs(observed_rps - prev)
        self.ewma_dev = self.alpha * dev_obs + (1 - self.alpha) * max(self.ewma_dev, 0.1)

        self.current_second = sec
        self.current_count = 1

        z = 0.0 if self.ewma_dev <= 0 else (observed_rps - self.ewma_rps) / self.ewma_dev
        return self.ewma_rps, z


@dataclass
class Decision:
    action: str
    risk: float
    reason: str


class AIDDoSGateway:
    """Gateway that scores each request and decides allow/challenge/block."""

    def __init__(
        self,
        bucket_capacity: int = 20,
        bucket_refill_rate: float = 10.0,
        challenge_threshold: float = 0.45,
        block_threshold: float = 0.75,
    ) -> None:
        self.bucket_capacity = float(bucket_capacity)
        self.bucket_refill_rate = bucket_refill_rate
        self.challenge_threshold = challenge_threshold
        self.block_threshold = block_threshold
        self.buckets: dict[str, TokenBucket] = {}
        self.stats = TrafficStats()
        self.blocklist: set[str] = set()

    def _get_bucket(self, ip: str) -> TokenBucket:
        if ip not in self.buckets:
            self.buckets[ip] = TokenBucket(self.bucket_capacity, self.bucket_refill_rate)
        return self.buckets[ip]

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1.0 / (1.0 + exp(-x))

    def _score(self, allowed_by_bucket: bool, z_score: float, path: str) -> float:
        rate_feature = 0.0 if allowed_by_bucket else 1.0
        anomaly_feature = max(0.0, min(3.0, z_score)) / 3.0
        sensitive_path_feature = 1.0 if path in {"/login", "/checkout", "/api/auth"} else 0.2
        linear = -2.0 + 2.4 * rate_feature + 1.8 * anomaly_feature + 0.8 * sensitive_path_feature
        return self._sigmoid(linear)

    def process_request(self, ip: str, path: str, now: float) -> Decision:
        if ip in self.blocklist:
            return Decision("block", 1.0, "ip_blocklisted")

        _, z_score = self.stats.update(now)
        bucket = self._get_bucket(ip)
        allowed_by_bucket = bucket.consume(now)
        risk = self._score(allowed_by_bucket, z_score, path)

        if risk >= self.block_threshold:
            self.blocklist.add(ip)
            return Decision("block", risk, "high_risk_detected")
        if risk >= self.challenge_threshold:
            return Decision("challenge", risk, "suspicious_traffic")
        return Decision("allow", risk, "normal_traffic")
