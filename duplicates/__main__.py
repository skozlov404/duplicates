import logging as log
import os
import hashlib
from argparse import ArgumentParser
from pathlib import Path
from collections import Counter, defaultdict
from itertools import takewhile
from concurrent.futures import ThreadPoolExecutor
from humanfriendly import parse_size, format_size


BUFFER_SIZE = 8192


def _positive_integer(s: str) -> int:
    i = int(s)
    if i < 0:
        raise ValueError()
    return i


def setup_logging(log_level: str) -> None:
    log.basicConfig(
        level=log_level
    )


def parse_arguments() -> dict:
    parser = ArgumentParser()

    parser.add_argument('workdir', default=Path(), type=Path, nargs='?')
    parser.add_argument('-v', '--verbose', action='store_const', const='DEBUG', default='INFO', dest='log_level')
    parser.add_argument('-s', '--min-size', type=parse_size, default=0)
    parser.add_argument('-t', '--hash-threads', type=_positive_integer, default=0)

    return vars(parser.parse_args())


def get_digest(f: Path) -> str:
    digest = hashlib.sha256()
    with f.open('rb') as fo:
        while True:
            data = fo.read(BUFFER_SIZE)
            if not data:
                return digest.hexdigest()
            digest.update(data)


def main():
    config = parse_arguments()
    setup_logging(config['log_level'])

    total_counter = 0
    size_counter = Counter()
    size_to_files = defaultdict(list)

    hash_counter = Counter()
    hash_to_files = defaultdict(list)
    hash_to_sizes = {}

    def hash_file(f: Path, size: int):
        log.debug(f"Calculating hash for {f}")
        digest = get_digest(f)

        hash_counter[digest] += 1
        hash_to_files[digest].append(f)
        hash_to_sizes[digest] = size

    threads = config['hash_threads'] or os.cpu_count()
    log.debug(f"Running {threads} hashing threads")

    futures = []
    with ThreadPoolExecutor(max_workers=threads) as tpe:
        for root, _, files in os.walk(config['workdir']):
            for f in files:
                full_path = Path(root, f)
                size = full_path.stat().st_size

                if size < config['min_size']:
                    continue

                total_counter += 1
                size_counter[size] += 1
                size_to_files[size].append(full_path)

                if size_counter[size] > 1:
                    # If there's more than one file of this size - calculate hash for it
                    futures.append(tpe.submit(hash_file, full_path, size))

                    if size_counter[size] == 2:
                        # If this is the second file of the same size - calculate digest for the first one too
                        futures.append(tpe.submit(hash_file, size_to_files[size][0], size))

        # Make sure to catch all exceptions
        for fut in futures:
            fut.exception()

    log.info(f"Total files: {total_counter}")

    sorted_hashes = sorted((x[0] for x in takewhile(lambda x: x[1] > 1, hash_counter.most_common())), key=lambda x: hash_to_sizes[x], reverse=True)

    for digest in sorted_hashes:
        print(f"SHA256: {digest}")
        print(f"Size: {format_size(hash_to_sizes[digest])}")
        print("Files:")
        for f in hash_to_files[digest]:
            print(f)
        print()

    log.info("Finished")


if __name__ == '__main__':
    main()
