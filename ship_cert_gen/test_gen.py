import pytest

from ship_cert_gen import create_certificate, ski_from_certificate


def test_ski_from_certificate():
    certificates = [
        (
            """-----BEGIN CERTIFICATE-----
MIIBvTCCAWOgAwIBAgIRA3afleU0kuA7gcMitS3BPI4wCgYIKoZIzj0EAwIwPjEL
MAkGA1UEBhMCREUxDTALBgNVBAoTBEVWQ0MxCTAHBgNVBAsTADEVMBMGA1UEAwwM
RVZDQ19IRU1TXzAxMB4XDTI0MTAxMDEyMTU0OFoXDTM0MTAwODEyMTU0OFowPjEL
MAkGA1UEBhMCREUxDTALBgNVBAoTBEVWQ0MxCTAHBgNVBAsTADEVMBMGA1UEAwwM
RVZDQ19IRU1TXzAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExmqx7kGUmhoI
9dQqXqDhW4h3KCzRUiLSEAcsJ/9+vdmK9ZWFdyaicpdaRqhdMHs3TU06X1vYUpeJ
tFlk/oJjC6NCMEAwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFPjJqiw7/mVtC2ud1YFVxe2vMJrFMAoGCCqGSM49BAMCA0gAMEUCIQDm
6HfgAnrwGPmiG4qCBt1eAj0PD3WC5YEBxM4TQr/QHAIgPqI3gpRXa8LdLzHhjjjW
fre3YMpHWgTcpzFBOOHtKkw=
-----END CERTIFICATE-----""",
            "f8c9aa2c3bfe656d0b6b9dd58155c5edaf309ac5",
        ),
        (
            """-----BEGIN CERTIFICATE-----
MIIBqDCCAU2gAwIBAgIUdwji21KV6JsZDc8DSh0WRKnAvYwwCgYIKoZIzj0EAwIw
QjENMAsGA1UECwwERGVtbzENMAsGA1UECgwERGVtbzELMAkGA1UEBhMCREUxFTAT
BgNVBAMMDERlbW8tVW5pdC0wMTAeFw0yNTAxMjAxNDA5MjlaFw0zNTAxMTgxNDA5
MjlaMEIxDTALBgNVBAsMBERlbW8xDTALBgNVBAoMBERlbW8xCzAJBgNVBAYTAkRF
MRUwEwYDVQQDDAxEZW1vLVVuaXQtMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAS+VlLhfconR4SttKAchQz4X2RCTNeMICX3utclXWsA10S1SlIG7lt+g3AzBm60
khqvD+/OKq0UsGErKEu7KS3/oyEwHzAdBgNVHQ4EFgQUfSOFDQhiCUSw0b5Bxwz1
j2+IaF4wCgYIKoZIzj0EAwIDSQAwRgIhAMuWajhKu+/jW7do/yuWOmAWHB5Hspiu
zzSztr2I4+VzAiEA7twxoWs8TFb78RV18ursv8qYWIeldPLRGXa6aYgfhKg=
-----END CERTIFICATE-----""",
            "7d23850d08620944b0d1be41c70cf58f6f88685e",
        ),
        (
            """-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUM21olfdo5sBeNPHGgFeB/acr60gwCgYIKoZIzj0EAwIw
QjENMAsGA1UECwwERGVtbzENMAsGA1UECgwERGVtbzELMAkGA1UEBhMCREUxFTAT
BgNVBAMMDERlbW8tVW5pdC0wMTAeFw0yNTAxMjAxNDE1MzFaFw0zNTAxMTgxNDE1
MzFaMEIxDTALBgNVBAsMBERlbW8xDTALBgNVBAoMBERlbW8xCzAJBgNVBAYTAkRF
MRUwEwYDVQQDDAxEZW1vLVVuaXQtMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASFW6avpo0zmsHo7oPdrPyxOUbh4vg/IVsCWeVJD97obDwlFPcD9ikvPwFTYS+6
DAyHtbCYRTLYnpqurBNqgeEioyEwHzAdBgNVHQ4EFgQU5moaXaKTVo6lZpwUf8YP
d8Vs+DcwCgYIKoZIzj0EAwIDSAAwRQIgO3Vm/laXF41kV3naFMnzW0OVOSm9t30O
2YXA5YiBD1kCIQDi1+YA0wpar0VnCgV2W7QsofrkCuq6k7lxEU+1MQMKsA==
-----END CERTIFICATE-----""",
            "e66a1a5da293568ea5669c147fc60f77c56cf837",
        ),
    ]

    for cert, expected_ski in certificates:
        assert ski_from_certificate(cert.encode()) == expected_ski


def test_ski_from_certificate_invalid_cert():
    with pytest.raises(ValueError):
        cert = """-----BEGIN CERTIFICATE-----
    SKIBIDDI YES YES YES
    -----END CERTIFICATE-----"""
        ski_from_certificate(cert.encode())


def test_ski_from_certificate_no_ski():
    with pytest.raises(ValueError, match="Client certificate does not provide a SKI"):
        cert = """ -----BEGIN CERTIFICATE-----
    MIIBhDCCASqgAwIBAgIUF2dh1ObfbQSkFcqzPmyy/xELD+4wCgYIKoZIzj0EAwIw
    QjENMAsGA1UECwwERGVtbzENMAsGA1UECgwERGVtbzELMAkGA1UEBhMCREUxFTAT
    BgNVBAMMDERlbW8tVW5pdC0wMTAeFw0yNTAxMjAxNDAzNDJaFw0zNTAxMTgxNDAz
    NDJaMEIxDTALBgNVBAsMBERlbW8xDTALBgNVBAoMBERlbW8xCzAJBgNVBAYTAkRF
    MRUwEwYDVQQDDAxEZW1vLVVuaXQtMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
    AAQlBI3Xv72HHnZdJWyQGtVTWS35JLTWUqn6YVSwKbJd5gsl5FAUSBeojSrJ18DT
    pV5BJDuYt1fh7h50tDc0Fd/xMAoGCCqGSM49BAMCA0gAMEUCICbA2laid7/PiAfL
    kyAtffW4I9Fn/IzyDLkFo9vRvMHzAiEAox360wqk/8+YmyRsaLncqqlGlI9LkBoM
    BKd7iAomBf4=
    -----END CERTIFICATE-----"""
        ski_from_certificate(cert.encode())


def test_create_certificate():
    organizational_unit = "Test Unit"
    organization = "Test Org"
    country = "DE"
    common_name = "Test Common Name"

    cert_pem, key_pem, ski = create_certificate(
        organizational_unit, organization, country, common_name
    )

    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert key_pem.startswith(b"-----BEGIN EC PRIVATE KEY-----")
    assert len(ski) == 40  # SKI should be 20 bytes, represented as 40 hex characters

    # Verify that the SKI from the certificate matches the returned SKI
    extracted_ski = ski_from_certificate(cert_pem)
    assert extracted_ski == ski
