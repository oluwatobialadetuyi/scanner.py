"""CLI entrypoint for the API scanner."""
import argparse
import sys
from api_scanner.scanner import Scanner
from api_scanner.report import generate_json_report, generate_html_report


def main(argv=None):
    p = argparse.ArgumentParser(description='API Scanner')
    p.add_argument('target', help='Base URL to scan, e.g. https://example.com')
    p.add_argument('--threads', type=int, default=10)
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('--out-json', default='report.json')
    p.add_argument('--out-html', default='report.html')
    p.add_argument('--paths-file', help='Optional file with additional paths (one per line)')
    args = p.parse_args(argv)

    paths = None
    if args.paths_file:
        try:
            with open(args.paths_file, 'r', encoding='utf-8') as fh:
                paths = [l.strip() for l in fh if l.strip()]
        except Exception as e:
            print('Could not read paths file:', e)
            sys.exit(1)

    s = Scanner(args.target, paths=paths, timeout=args.timeout, threads=args.threads)
    print('Discovering and scanning endpoints...')
    results = s.run()
    print('Scan complete. Generating reports...')
    generate_json_report(s.base_url, results, args.out_json)
    generate_html_report(s.base_url, results, args.out_html)
    print('Reports written to', args.out_json, args.out_html)


if __name__ == '__main__':
    main()
