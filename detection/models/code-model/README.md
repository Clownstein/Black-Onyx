# Code model inference artifacts

The inference service reads a **signed model package directory** at `/app/artifacts`.
The directory must contain `model.joblib`, the package metadata, `checksums.txt`,
and `signature.json` produced by `black_onyx_model_package.build_model_package`.
Loose output from `training/train.py` is an intermediate training artifact and is
not accepted by the inference service.

For Compose, set `BLACK_ONYX_CODE_MODEL_ARTIFACTS_DIR` to the host path of the
`model-package` directory and `TRAINING_ARTIFACT_SIGNING_KEY` to the same secret
used by the training orchestrator. For Helm, mount a PVC whose root is the
`model-package` directory through `codeModel.artifactClaimName`; the key in
`codeModel.artifactSigningSecretKey` must exist in `.Values.secrets.name`.
Until a signed package is mounted, `/health/ready` returns 503 and prediction
requests are unavailable.

The package is copied to a private temporary directory and verified before
the `joblib` payload is deserialized. A signing key is required even in local
development. Treat that key as a production secret: anyone who can read it can
produce a package that the inference service will trust.
