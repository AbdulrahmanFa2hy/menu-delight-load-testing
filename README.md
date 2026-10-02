# Menu Delight - Distributed Cloud Load Testing Suite

High-throughput distributed load testing engine powered by GitHub Actions, Grafana k6, and multi-region cloud runners.

## Architecture
- **Distributed Matrix:** Spawns 10 parallel GitHub runner nodes distributed across Microsoft Azure data centers worldwide.
- **Realistic Multi-Experience Traffic:**
  - **60% Public Menus:** Visitor shell HTML, edge-cached menu JSON, and batched analytics event streaming.
  - **25% Image Tracking AR:** Edge function session creation, Cloudflare Worker cached target image & 3D GLB model download, and batched camera tracking telemetry.
  - **15% Arcade Games:** Edge entertainment session lifecycle, immutable XR asset delivery, and score tracking.
- **Automated Results Aggregator:** A dedicated final job downloads all runner metrics, combines global requests, global RPS, and calculates average p95 latencies and Cloudflare cache HIT ratios into a unified GitHub Step Summary table.

## Running the Benchmark
1. Go to the **Actions** tab in this repository.
2. Select **"Distributed Multi-Experience Load Test (10,000+ VUs)"**.
3. Click **Run workflow**:
   - Choose total VUs (e.g. `10000`, `15000`, `20000`).
   - Choose duration (e.g. `60`, `120` seconds).
4. Monitor the live matrix runs and inspect the final **Global Benchmark Results** summary.
