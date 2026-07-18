import argparse
from pathlib import Path

from pipeline.image_builder import build_signed_image
from pipeline.keygen import generate_keypair


def main():
    parser = argparse.ArgumentParser(prog="bolt")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen_p = sub.add_parser("keygen", help="Generate OEM signing keypair")
    keygen_p.add_argument("--out", default="keys")

    sign_p = sub.add_parser("sign", help="Sign a firmware payload")
    sign_p.add_argument("payload")
    sign_p.add_argument("--version", type=int, required=True)
    sign_p.add_argument("--rollback-index", type=int, required=True)
    sign_p.add_argument("--key", required=True, help="Path to private key PEM")
    sign_p.add_argument("--out", default=None)

    args = parser.parse_args()

    if args.command == "keygen":
        priv, pub = generate_keypair(args.out)
        print(f"Private: {priv}\nPublic:  {pub}")

    elif args.command == "sign":
        payload = Path(args.payload).read_bytes()
        image = build_signed_image(payload, args.version, args.rollback_index, args.key)
        out_path = Path(args.out) if args.out else Path(args.payload).with_suffix(".fwimg")
        out_path.write_bytes(image)
        print(f"Signed image written: {out_path} ({len(image)} bytes)")


if __name__ == "__main__":
    main()
