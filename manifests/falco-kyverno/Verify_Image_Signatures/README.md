# Verify Image Signatures

| Property | Value |
|---|---|
| **Type** | Kyverno (ImageValidatingPolicy) |
| **Kyverno Action** | Verifies that container images are signed with Cosign before admission. Unsigned images are flagged (Audit) or rejected (Deny). |
| **Falco Detection** | N/A — supply chain verification happens at admission time. |

## Description
Supply chain attacks targeting container images (e.g., injecting malicious layers, tag hijacking) are a critical Kubernetes threat vector. This `ImageValidatingPolicy` enforces that all container images from `ghcr.io/*` are signed using [Cosign](https://github.com/sigstore/cosign) with a public key. The policy uses Kyverno's CEL function `verifyImageSignatures()` to cryptographically verify image signatures at admission time.

> **Policy Type: `ImageValidatingPolicy`** — A specialized policy type designed exclusively for image signature and attestation verification. It provides CEL functions (`verifyImageSignatures`, `verifyAttestationSignatures`, `extractPayload`) not available in standard `ValidatingPolicy`.

---

## Kyverno Policy Manifest
```yaml
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: verify-image-signatures
  annotations:
    policies.kyverno.io/title: Verify Image Signatures
    policies.kyverno.io/category: Supply Chain Security
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      Verifies that all container images from approved registries are signed
      using Cosign. Unsigned images are rejected to prevent supply chain
      tampering attacks.
  labels:
    app.kubernetes.io/part-of: kyverno-falco-policies
spec:
  webhookConfiguration:
    timeoutSeconds: 15
  validationActions: [Audit]
  matchConstraints:
    resourceRules:
      - apiGroups: ['']
        apiVersions: ['v1']
        operations: [CREATE, UPDATE]
        resources: [pods]
  matchImageReferences:
    - glob: 'ghcr.io/*'
  attestors:
    - name: cosign
      cosign:
        key:
          data: |
            -----BEGIN PUBLIC KEY-----
            REPLACE_WITH_YOUR_COSIGN_PUBLIC_KEY
            -----END PUBLIC KEY-----
  validations:
    - expression: >-
        images.containers.map(image,
          verifyImageSignatures(image, [attestors.cosign])
        ).all(e, e > 0)
      message: "Image signature verification failed. All images must be signed with Cosign."
```

---

## Detailed Explanation

### Key Fields
| Field | Purpose |
|---|---|
| `matchImageReferences` | Glob patterns to select which images to verify (e.g., `ghcr.io/*`). Only matched images are verified. |
| `attestors` | Trust authorities (Cosign public keys, Keyless OIDC identities, or Notary certificates). |
| `validations` | CEL expressions using image-specific functions to verify signatures. |

### CEL Functions Available in ImageValidatingPolicy
| Function | Purpose |
|---|---|
| `images.containers` | Returns list of all container images in the pod spec. |
| `verifyImageSignatures(image, [attestors])` | Verifies image signature. Returns count of verified signatures (> 0 = verified). |
| `verifyAttestationSignatures(image, attestation, [attestors])` | Verifies attestation signatures (e.g., SBOM, vulnerability scans). |
| `extractPayload(image, attestation)` | Extracts in-toto attestation payload for inspection. |

### Cosign Attestor Types
- **Public Key** (`key.data`): Inline PEM-encoded public key.
- **KMS** (`key.kms`): KMS URI (e.g., `awskms://arn:aws:kms:...`).
- **Keyless** (`keyless.identities`): OIDC-based verification with `subject` and `issuer`.

---

## How to Setup

### 1. Generate a Cosign Key Pair
```bash
cosign generate-key-pair
```

### 2. Sign Your Images
```bash
cosign sign --key cosign.key ghcr.io/your-org/your-image:v1.0
```

### 3. Replace the Public Key
Replace `REPLACE_WITH_YOUR_COSIGN_PUBLIC_KEY` in the policy with the contents of `cosign.pub`.

### 4. Change to Enforce Mode
Once verified, change `validationActions: [Audit]` to `validationActions: [Deny]` to block unsigned images.
