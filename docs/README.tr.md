# IronShim-rs Dokumantasyon (TR)

Bu klasor, IronShim-rs icin operator ve entegrator giris noktasidir.

## Buradan Basla

- [Proje README](../README.md)
- [Mimari Derin Inceleme](ARCHITECTURE.md)
- [Guvenlik Modeli](SECURITY_MODEL.md)
- [Operasyon Rehberi](OPERATIONS.md)
- [Artifact Chain](ARTIFACT_CHAIN.md)
- [Canli Dogrulama Rehberi](LIVE_VALIDATION.md)
- [English Documentation Index](README.en.md)

## Okuma Sirasi

### Kutuphaneyi Kernel'e Gomuyorsan

1. [Mimari Derin Inceleme](ARCHITECTURE.md)
2. [Guvenlik Modeli](SECURITY_MODEL.md)

### Build Ve Release Tarafini Sen Yonetiyorsan

1. [Operasyon Rehberi](OPERATIONS.md)
2. [Artifact Chain](ARTIFACT_CHAIN.md)

### Gercek Donanim Dogrulamasini Sen Yapiyorsan

1. [Canli Dogrulama Rehberi](LIVE_VALIDATION.md)
2. [Operasyon Rehberi](OPERATIONS.md)

## Dokuman Kapsami

Bu dokumanlar repodaki mevcut gercegi anlatir:

- fail-closed resource policy
- kanonik manifest hashing ve signature hook'lari
- lifecycle ve interrupt containment
- TUF-style artifact yayini ve rollback-aware client dogrulamasi
- Linux DOE/SPDM, SR-IOV, AER/DPC, `iommufd`, VFIO dogrulama yuzeyi
- Kani, fuzzing ve Miri assurance hatlari

## Lisans

IronShim-rs, AGPL-3.0-only ile lisanslanmistir. Bkz. [LICENSE](../LICENSE).
