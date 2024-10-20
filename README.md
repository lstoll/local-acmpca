# local-acmpca

This is a local version of a subset of the [AWS Private CA](https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html) API, used for development and testing. Inspired by [local-kms](https://github.com/nsmithuk/local-kms)

Status: Basic CA and cert issuance works. Not throughly compared to real-world PCA API usage. Only EC keys, and non-hierachial CAs works currently. PR's welcome.

See [e2e_test.go](e2e_test.go) for an example of what's supported.

The state store can be seeded from a file, this can be useful for development configurations where an externally provisioned CA is expected, and the ARN should be consistent across runs. By default a state file without key/cert will be updated in place on first run, this result can then be committed.

Example seed file for automatic provisioning:

```
CAs:
- arn: arn:aws:acm-pca:eu-west-2:111122223333:certificate-authority/48786ae7-cb4a-474a-b9a7-23aa663d78b1 #  uuidgen | tr "[:upper:]" "[:lower:]"
  cn: Example Seeded CA
  keyAlgorithm: EC_prime256v1
```
