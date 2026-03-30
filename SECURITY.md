# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in codewash, please **do not** open a public GitHub issue.

Instead, please report it privately by emailing security@example.com with:

1. A clear description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested fix (if you have one)

We will acknowledge receipt within 48 hours and work with you to resolve the issue confidentially before public disclosure.

## Security Considerations

### What codewash is designed to do:

- Strip sensitive values from non-encrypted configuration files
- Create reversible, offline anonymized copies for safe sharing with AI assistants
- Provide consistent value replacement across repository trees
- Work with plaintext infrastructure code (YAML, Bash, Python, Terraform, etc.)

### What codewash is NOT designed for:

- Protecting encrypted files or secrets managers (vaults, SecretManager, etc.)
- Anonymizing binary files or compiled code
- Protecting against attacks that have access to the mapping file
- Encrypting data at rest or in transit
- Protecting against memory dumps or side-channel attacks

### Important Notes:

1. **The mapping file contains original secrets** — keep `.codewash-map.json` private and secure
2. **Reversibility is a feature, not a bug** — if someone has both the anonymized repo AND the mapping file, they can recover originals
3. **Regex-based detection has limits** — sophisticated obfuscation may evade patterns
4. **Text replacement is literal** — multi-line values, concatenation, or dynamic code generation may not be detected
5. **No external validation** — codewash cannot verify if a detected "password" is actually sensitive

### Best Practices:

- Use codewash to prepare code **before** sharing with AI assistants
- Keep the mapping file in a secure location (not in version control)
- Review the anonymized output manually for any missed sensitive data
- Use allowlist/denylist to customize detection for your environment
- Consider layering codewash with other security practices (input sanitization, role-based access, etc.)

## Supported Versions

Only the latest version of codewash receives security updates. Users are encouraged to upgrade promptly.

## Security Updates

Security patches will be released as soon as possible after a vulnerability is confirmed and fixed.
