# Verify Image Signatures

| Property | Value |
|---|---|
| **Type** | Kyverno (ImageValidatingPolicy) |
| **Kyverno Action** | Verifies that container images are signed with Cosign before admission. Unsigned images are flagged (Audit) or rejected (Deny). |
| **Falco Detection** | N/A — supply chain verification happens at admission time. |

## Description
Supply chain attacks targeting container images (e.g., injecting malicious layers, tag hijacking) are a critical Kubernetes threat vector. This `ImageValidatingPolicy` enforces that all container images from `ghcr.io/*` are signed using [Cosign](https://github.com/sigstore/cosign) with a public key. The policy uses Kyverno's CEL function `verifyImageSignatures()` to cryptographically verify image signatures at admission time.

## Detailed Explanation

### Kyverno CEL ImageValidatingPolicy Breakdown

```yaml
spec:
  matchImageReferences:
    - glob: 'ghcr.io/*'
  attestors:
    - name: cosign
      cosign:
        key:
          data: | ...
  validations:
    - expression: >-
        images.containers.map(image,
          verifyImageSignatures(image, [attestors.cosign])
        ).all(e, e > 0)
```

| CEL Function / Fragment | What It Does | Why It's Needed |
|---|---|---|
| `kind: ImageValidatingPolicy` | Kyverno image signature validation policy type. | Exposes specialized Cosign and in-toto attestation verification functions in CEL. |
| `matchImageReferences: [glob: 'ghcr.io/*']` | Filters images by domain pattern using globs. | Restricts signature enforcement to container images sourced from targeted registries. |
| `images.containers` | CEL built-in helper returning list of container images in target pod spec. | Extracts image reference URIs for evaluation. |
| `verifyImageSignatures(image, [attestors.cosign])` | Cosign signature check function. | Cryptographically verifies if `image` has a valid Cosign signature signed by the configured public key. Returns count of verified signatures (`> 0`). |
| `.all(e, e > 0)` | CEL list macro: checks that verified signature count `e` is greater than 0 for all container images. | Enforces that **every** container image in the pod possesses a valid cryptographic signature. |

---

### ℹ️ Why There Is No Falco Companion Rule

Image signature verification relies on public key cryptography to check signatures against container registries during admission before image pull.

* **Admission Cryptography**: Cosign signature checks require network calls to image registries and public key matching during admission.
* **Registry Image Restrictions**: Runtime registry enforcement is handled by [Restrict Image Registries](../Restrict_Image_Registries/README.md).

---

### 🛡️ Problem Statement — What Are We Preventing?

Container images are the fundamental unit of deployment in Kubernetes. If an attacker can tamper with an image between build and deployment, they can inject arbitrary code into production — affecting every pod that uses that image. Without cryptographic signature verification, organizations are blind to image tampering:

* **Supply Chain Attacks (MITRE ATT&CK: T1195.002)**: Attackers can compromise CI/CD pipelines, container registries, or build systems to inject malicious code into container images. High-profile attacks like SolarWinds and Codecov demonstrated that supply chain compromise can go undetected for months while affecting thousands of organizations.
* **Tag Hijacking**: Container image tags are mutable — an attacker who gains write access to a registry can overwrite an existing tag (e.g., `v1.5.0`) with a malicious image. All subsequent deployments using that tag will pull the compromised image. Signature verification ensures that the image content matches what was originally signed by the authorized builder.
* **Registry Compromise**: If a container registry is compromised, all images stored in it become untrusted. Without signature verification, there's no way to distinguish between legitimate images and those modified by the attacker. Cryptographic signatures provide an independent trust anchor that remains valid even if the registry is compromised.
* **Insider Threats**: A malicious insider with registry push access can modify production images to include backdoors, data exfiltration code, or crypto miners. Signature verification ensures that only images signed by authorized keys can be deployed, regardless of who pushed them to the registry.
* **Compliance Requirements**: Frameworks like SLSA (Supply Chain Levels for Software Artifacts), NIST SSDF, and Executive Order 14028 require software artifact signing and verification as a mandatory supply chain security practice.

**Kyverno prevents this** by using an `ImageValidatingPolicy` that cryptographically verifies Cosign signatures on every container image at admission time. Unsigned or incorrectly signed images are flagged (Audit) or rejected (Deny), ensuring that only trusted, verified images run in the cluster.

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

## Test Scenarios & Manifest Examples

### 1. ✅ PASS Case — Validly Signed Cosign Image (`ghcr.io/*`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pass-signed-image
  namespace: default
spec:
  containers:
    - name: app
      image: ghcr.io/your-org/signed-app:v1.0.0
```
* **Result**: **PASS** — Kyverno invokes `verifyImageSignatures()` against `attestors.cosign`. Cryptographic signature matches public key. Returns count `> 0`.

---

### 2. ❌ FAIL Case — Unsigned Image from Matched Domain (`ghcr.io/*`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-fail-unsigned-image
  namespace: default
spec:
  containers:
    - name: app
      image: ghcr.io/your-org/unsigned-app:v1.0.0
```
* **Result**: **FAIL** — `verifyImageSignatures()` returns `0` (no valid signature found). Denied with message `"Image signature verification failed. All images must be signed with Cosign."`

---

### 3. 🛡️ EXEMPT CASE — Image Outside Matched Glob Pattern
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-exempt-other-registry
  namespace: default
spec:
  containers:
    - name: app
      image: registry.k8s.io/pause:3.9
```
* **Result**: **PASS (EXEMPT)** — `matchImageReferences: ['ghcr.io/*']` skips verification for images outside the `ghcr.io/*` pattern.

---

## How to Setup & Test

### 1. Generate Cosign Key Pair
```bash
cosign generate-key-pair
```

### 2. Sign Target Image
```bash
cosign sign --key cosign.key ghcr.io/your-org/your-image:v1.0.0
```

### 3. Apply Policy with Public Key
Replace `REPLACE_WITH_YOUR_COSIGN_PUBLIC_KEY` in `kyverno.yaml` with your `cosign.pub` contents and apply.

### 4. Admission Control Dry-Run Check
```bash
# Test dry-run deployment of signed/unsigned images
kubectl apply -f - --dry-run=server <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-signed-pod
  namespace: default
spec:
  containers:
    - name: app
      image: ghcr.io/your-org/your-image:v1.0.0
EOF
```

