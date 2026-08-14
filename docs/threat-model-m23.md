# M23 Identity Trust-Boundary Threat Model

M23 authenticates the workload and actor before a tool call reaches policy
evaluation or execution. The implementation exposes a provider-neutral
`IdentityProvider` interface so a deployment can use SPIFFE/SPIRE or another
established attestation provider. The bundled HMAC provider is a deterministic
test adapter only; its key material is not suitable for production.

## Assets and trust boundaries

- **Principal identity:** trust domain, subject, issuer, mapped roles, expiry,
  and a stable non-secret identity reference.
- **Governance decision:** the policy, delegation state, action, context, and
  verified identity reference that produced the decision.
- **Approval authority:** named roles and authenticated approver references.
- **Historical evidence:** redacted audit events that must survive credential
  rotation and process restart.

The untrusted boundary is the incoming `ToolCall` and its credential. The
trusted boundary begins only after the configured provider verifies the
credential, the verifier checks the trust domain and time window, and the
subject matches the actor selected by the caller.

## Threats and controls

| Threat | Control | Evidence |
|---|---|---|
| Missing or unauthenticated credential | Configured `RuntimeAdapter` rejects the call before policy execution and tool invocation. | `test_unauthenticated_expired_wrong_domain_and_impersonated_calls_fail_closed` |
| Expired or not-yet-valid credential | Provider validates issuance and expiry against decision time. | M23 expiry acceptance test |
| Wrong trust domain or issuer | Provider and verifier require the configured domain and issuer. | M23 wrong-domain test |
| Actor impersonation | Verified subject must equal the actor bound to the tool call. | M23 impersonation test |
| Credential tampering | Signed payload is verified with constant-time signature comparison. | M23 forged-credential test |
| Role confusion | Explicit role mapping rejects unmapped claims and sorts mapped roles deterministically. | M23 role-mapping test |
| Delegation provenance loss | Authority proofs and grant snapshots carry the verified identity reference. | M23 delegation proof test |
| Unauthorized approval vote | Secure approval mode requires an identity whose mapped roles contain the voted role. | M23 approval-role test |
| Audit invalidation during rotation | Audit fingerprints use a stable principal reference, not the rotating credential signature. | M23 rotation/replay test |
| Secret leakage into evidence | Audit events record only identity reference and mapped roles, never raw credentials or signing keys. | M23 audit redaction assertion |

## Residual risks and deployment requirements

- Production must use an established workload identity provider, key rotation,
  revocation, and attestation policy. The test provider intentionally does not
  provide these capabilities.
- Trust-domain configuration and role mappings are security-sensitive deployment
  configuration and must be reviewed and versioned with policy changes.
- Clock synchronization is required for reliable expiry enforcement. A service
  boundary should define an explicit bounded clock-skew policy before rollout.
- Credential references and identity subjects may still be sensitive metadata;
  operators should apply the project’s retention and access controls.
- M23 does not implement a CA, multi-tenant identity service, or custom
  cryptographic protocol.
