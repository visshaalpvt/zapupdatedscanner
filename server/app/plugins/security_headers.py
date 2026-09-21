import urllib.request
from urllib.parse import urlparse

from .base import ScanContext, ScannerPlugin


class SecurityHeadersPlugin(ScannerPlugin):
    name = "security_headers"
    label = "Security Headers"
    description = "Quick smoke-test for security headers and transport protections."

    def run(self, ctx: ScanContext):
        url = ctx.target.strip()
        if not url:
            raise ValueError("Target URL is required")
        parsed = urlparse(url)
        scheme = (parsed.scheme or "https").lower()

        ctx.log(f"Checking security headers for {url}")
        req = urllib.request.Request(url, method="GET")
        ctx.progress(10)
        ctx.checkpoint()

        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
                status = getattr(response, "status", 200)
                ctx.log(f"Received HTTP {status} from target")
        except Exception as exc:
            raise RuntimeError(f"Could not reach target: {exc}")

        checks = [
            ("csp", "content-security-policy", "Content Security Policy"),
            ("hsts", "strict-transport-security", "HTTP Strict Transport Security"),
            ("x_content_type_options", "x-content-type-options", "X-Content-Type-Options"),
            ("x_frame_options", "x-frame-options", "X-Frame-Options"),
            ("referrer_policy", "referrer-policy", "Referrer Policy"),
            ("permissions_policy", "permissions-policy", "Permissions Policy"),
        ]

        weak_findings = []
        for key, header_name, label in checks:
            ctx.progress(20 + (60 * checks.index((key, header_name, label)) / max(len(checks), 1)))
            if not headers.get(header_name):
                weak_findings.append(("medium", f"Missing {label}", url, f"The response does not include the {label} header."))

        cookies = headers.get("set-cookie", "")
        if cookies:
            if "httponly" not in cookies.lower():
                weak_findings.append(("medium", "Cookie missing HttpOnly", url, "The application sets cookies without the HttpOnly flag."))
            if "secure" not in cookies.lower():
                weak_findings.append(("medium", "Cookie missing Secure", url, "Cookies are not marked Secure."))
            if "samesite" not in cookies.lower():
                weak_findings.append(("low", "Cookie missing SameSite", url, "The application does not set SameSite on cookies."))

        if scheme == "http":
            weak_findings.append(("high", "Plain HTTP is enabled", url, "The target is served over plain HTTP instead of HTTPS."))

        if "server" in headers:
            server = headers["server"]
            if server and not any(token in server.lower() for token in ("cloudflare", "nginx", "apache", "iis")):
                weak_findings.append(("info", "Version disclosure via Server header", url, f"The response exposes a server signature: {server}."))

        for severity, title, target_url, description in weak_findings:
            ctx.finding(severity, title, target_url, description)
            ctx.log(f"Finding: {title}")
            ctx.progress(min(95, ctx.progress_value + 5))
            ctx.checkpoint()

        if not weak_findings:
            ctx.finding("info", "Security headers look healthy", url, "No obvious header weakness was detected in the quick smoke test.")

        ctx.progress(100)
        ctx.log("Security headers smoke test finished.")
        return ctx
