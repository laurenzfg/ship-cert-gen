from ship_cert_gen.gen import create_certificate


def main() -> None:
    pub_pem, priv_pem, ski = create_certificate("Demo", "Demo", "DE", "Demo-Unit-01")

    print("Public key:\n", pub_pem.decode())
    print("Private key:\n", priv_pem.decode())
    print("SKI:", ski)


if __name__ == "__main__":
    main()
