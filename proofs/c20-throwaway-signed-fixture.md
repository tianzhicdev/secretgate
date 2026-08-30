# ethkey-lite-proof v1
created: 2026-08-30T20:15:40Z
signer: 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69
sha256: 818980819778c8fb1733d3cbb9c9010047f37d7d9b1703bfd595f2e81b4f888e
note: c20 negative-control fixture: GENUINE receipt by the PUBLIC throwaway key (pk=3). Signature real, signer NOT a fleet address. Passes bare verify; must fail --require against any fleet address.
signature: 0x0bcd783e51eac5c82b730ae8be50b45ea8dc5e3758c89ea3061ad89d1de58c104e8c991a2ca22003961e627732f496209706db8418c0d6510e4b5307d16591e61b

Signed scope: created + sha256 fields (not the note). Re-verify with
'ethkey.py verify <this file> --require <addr>' or ethers.verifyMessage
on the canonical string:
  ethkey-lite-proof v1\ncreated:<created>\nsha256:<sha256>

-----BEGIN PAYLOAD-----
YzIwIG5lZ2F0aXZlLWNvbnRyb2wgcGF5bG9hZDogYSBnZW51aW5lIHJlY2VpcHQgc2lnbmVkIGJ5
IHRoZSBQVUJMSUMgdGhyb3dhd2F5IGtleSAocGs9MykuIFNpZ25hdHVyZSBpcyByZWFsLCBzaWdu
ZXIgaXMgTk9UIGEgZmxlZXQgYWRkcmVzcy4gTXVzdCBwYXNzIGJhcmUgdmVyaWZ5IGFuZCBmYWls
IC0tcmVxdWlyZSBhZ2FpbnN0IGFueSBmbGVldCBhZGRyZXNzLgo=
-----END PAYLOAD-----
