# Keisu Capital Contracts

Contracts used in the Keisu Capital custody system.

## Contracts

```ml
factory
├── OrgValidatorCoreFactory — "Factory for OrgValidatorCore (using TransparentStaticProxy)"
proxy
├─ TransparentStaticProxy — "Simple, non-upgradeable transparent proxy"
core
├─ OrgValidatorCore — "parent registry for an org that validates authorizations from child safe contracts"
```