import time

from .base import ScanContext, ScannerPlugin


class SlowTestPlugin(ScannerPlugin):
    name = "slow_test"
    label = "Slow Test Scanner"
    description = "Test-only scanner executing 8 distinct steps with live progress updates."

    def run(self, ctx: ScanContext):
        steps = 8
        ctx.log(f"Starting slow test scanner for {ctx.target} (8 steps)")
        ctx.progress(0.0)

        for step in range(1, steps + 1):
            ctx.checkpoint()
            pct = round((step / steps) * 100.0, 1)
            ctx.progress(pct)
            ctx.log(f"Slow test step {step}/{steps} completed ({pct}%)")
            time.sleep(0.35)

        ctx.checkpoint()
        ctx.finding("info", "Slow Test Completed", ctx.target, "All 8 execution steps finished cleanly.")
        ctx.progress(100.0)
        ctx.log("Slow test scan completed successfully.")
        return ctx
