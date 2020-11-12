import secrets, argparse


def main(args):
    length = args.length
    api_key = secrets.token_urlsafe(length)
    print(api_key)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--length", type=int, help="desired length of random key")
    args = parser.parse_args()
    main(args)