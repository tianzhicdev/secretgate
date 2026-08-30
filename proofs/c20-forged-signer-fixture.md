# ethkey-lite-proof v1
created: 2026-08-30T20:15:40Z
signer: 0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15
sha256: 0c1792c641689020586a7d9b9a348d1155372558d03db1d41a7b0441fec802c3
note: c20 negative-control fixture: VALID throwaway-key signature (pk=3, public) with a FORGED signer header claiming the A wallet addr. This file is the ATTACK sample, NOT a release receipt. CI asserts every verifier rejects it.
signature: 0x800658fb9e099b4a895ae4546f1722e332e03b0a5a1a903936e44fb56f98b34657a6f46da893895621f4bcdf4dfcb420501efb83d23426c928ef50f7d0454ded1b

Signed scope: created + sha256 fields (not the note). Re-verify with
'ethkey.py verify <this file> --require <addr>' or ethers.verifyMessage
on the canonical string:
  ethkey-lite-proof v1\ncreated:<created>\nsha256:<sha256>

-----BEGIN PAYLOAD-----
YzIwIG5lZ2F0aXZlLWNvbnRyb2wgcGF5bG9hZDogYSBWQUxJRCBzaWduYXR1cmUgYnkgdGhlIFBV
QkxJQyB0aHJvd2F3YXkga2V5IChwaz0zKSBzaGlwcGVkIHdpdGggYSBGT1JLRUQgc2lnbmVyIGhl
YWRlciBjbGFpbWluZyB0aGUgQSB3YWxsZXQgYWRkciAoMHhGRDQwLi5hY0MxNSkuIFRoaXMgZmls
ZSBpcyB0aGUgQVRUQUNLIHNhbXBsZSwgbm90IGEgcmVjZWlwdC4gRG8gbm90IHRydXN0IHRoZSBz
aWduZXIgbGluZS4K
-----END PAYLOAD-----
