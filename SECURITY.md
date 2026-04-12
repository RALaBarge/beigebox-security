# Security Policy

## Reporting a Vulnerability

**Do not** open a public issue for security vulnerabilities. Instead, email your report to security@ralabarge.dev with:

- **Title**: Brief description of the vulnerability
- **Affected version(s)**: Which beigebox-security versions are affected
- **Description**: Technical details and proof-of-concept (if possible)
- **Impact**: What an attacker could do if this vulnerability is exploited
- **Proposed fix** (optional): Any ideas on how to fix it

We will acknowledge receipt within 48 hours and provide an estimated timeline for a fix.

## Security Response Timeline

- **Acknowledgment**: Within 48 hours of report
- **Investigation & patch development**: 3-7 days depending on severity
- **Release**: We will issue a security release as soon as the fix is ready
- **Disclosure**: We will disclose the vulnerability details 30 days after the public fix is released

## Severity Levels

| Level | Description | Response Time |
|-------|-------------|----------------|
| **Critical** | Security bypass (validation disabled, memory not verified, poisoning undetected) | 24 hours |
| **High** | Reduced effectiveness (detection rates drop, false negatives increase) | 2-3 days |
| **Medium** | Information disclosure, performance issue | 5-7 days |
| **Low** | Minor issues, documentation | Next release |

## Security Best Practices

### For beigebox-security Users

1. **Keep beigebox-security updated**: Security patches are released regularly. Run `pip install --upgrade beigebox-security` to get the latest version.

2. **Run with appropriate isolation**: Deploy in Docker or a VM to limit blast radius:
   ```bash
   docker run -p 8001:8001 beigebox-security:latest
   ```

3. **Restrict network access**: Only expose to trusted networks:
   ```bash
   # Good: Localhost only during development
   beigebox-security server --host 127.0.0.1 --port 8001
   
   # Good: Internal network with firewall rules
   # Bad: Expose to public internet without authentication
   ```

4. **Enable TLS for production**: Use HTTPS to prevent credential/data interception:
   ```bash
   beigebox-security server --ssl-certfile /path/to/cert.pem --ssl-keyfile /path/to/key.pem
   ```

5. **Audit logging**: Monitor and rotate logs:
   ```bash
   # View audit logs
   sqlite3 ~/.beigebox/memory_integrity.db "SELECT * FROM audit_log LIMIT 100"
   ```

6. **Baseline management**: Regularly review and update anomaly baselines:
   ```bash
   # Reset if you've made legitimate system changes
   curl -X POST http://localhost:8001/v1/security/anomaly/baseline/reset
   ```

### For Contributors

1. All commits should be signed (`git commit -S`)
2. All pull requests must pass security checks:
   - `pip-audit` for dependency vulnerabilities
   - `bandit` for code-level issues
   - `semgrep` for pattern-based security flaws
3. Changes to validation logic require extensive test coverage
4. New routers should use defense-in-depth (multiple validation tiers)
5. Cryptographic changes (HMAC, signatures) need careful review

## Known Limitations

### RAG Poisoning Detection

- **Baseline assumption**: Assumes your initial corpus is clean. If poisoned data was already injected, baseline is compromised.
- **Algorithm limits**: Each algorithm has false positive/negative trade-offs. Ensemble mode helps but isn't perfect.
- **Dimensionality**: Works best on embeddings 100-1536 dimensions. Extreme dimensions may need tuning.

### MCP Parameter Validation

- **Whitelist-based**: Only detects known attack patterns. Novel attack vectors may bypass detection.
- **Semantic understanding**: Semantic tier may not catch sophisticated command injection.
- **Tool-specific rules**: Some tools may have unique attack surfaces not covered.

### API Anomaly Detection

- **Baseline drift**: Normal usage patterns change over time. Re-baseline periodically.
- **Distributed systems**: Z-score detection works for single-instance deployments. Multi-instance requires different approach.
- **Timing attacks**: Doesn't detect attacks based on timing/side-channels.

### Memory Integrity

- **Key management**: The security of HMAC-SHA256 depends on keeping the key secret. Store keys in a secure key management system (AWS KMS, HashiCorp Vault, etc.) in production.
- **Signature verification**: Protects against tampering in transit. Doesn't protect against memory-resident malware.
- **Replay attacks**: Timestamps prevent replay but can be spoofed if clock is compromised.

## Deployment Security Checklist

- [ ] Run beigebox-security in a container or VM
- [ ] Restrict network access (firewall rules, VPC, network policy)
- [ ] Enable TLS for all connections
- [ ] Rotate baseline models regularly
- [ ] Monitor and audit all security decisions
- [ ] Keep dependencies updated (`pip-audit --fix`)
- [ ] Store secrets in a KMS (don't hardcode)
- [ ] Enable logging for all API calls
- [ ] Test false positive rates in your environment

## Dependency Scanning

We use `pip-audit` to continuously check for vulnerable dependencies. Run it yourself:

```bash
pip-audit --desc
```

Update vulnerable dependencies immediately:

```bash
pip install --upgrade beigebox-security
```

## Security Releases

Security releases are issued as `X.Y.Z` (no `-beta` tags) and announced on:

- GitHub Releases page
- Project README (pinned notice)
- Email to watchers (if subscribed)

## Third-Party Integration

If you integrate beigebox-security with other systems:

1. **Validate integration points**: Don't assume the upstream system is trustworthy
2. **Use defense-in-depth**: Don't rely solely on beigebox-security
3. **Monitor both sides**: If one side is compromised, assume the other is too
4. **Test failure modes**: What happens if beigebox-security goes down? Does your system fail safely?

## Performance & Resource Limits

In production, monitor resource usage:

```bash
# Check memory and CPU usage
docker stats beigebox-security

# Monitor database size
ls -lh ~/.beigebox/*.db
```

Set reasonable limits:

```yaml
# docker-compose.yml
services:
  beigebox-security:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
```

## Contact

For security inquiries: security@ralabarge.dev

Please allow 48 hours for initial response.
