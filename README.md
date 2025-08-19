# ext-js-hunter

## Purpose
`ext-js-hunter` is a tool designed to identify and analyze externally hosted JavaScript files on websites. It helps security researchers and developers understand the external dependencies of a website, which can be critical for identifying potential security risks or compliance issues.

### What it does:
- Loads websites in a headless Chromium browser using Selenium.
- Inspects browser logs to extract JavaScript resources.
- Classifies JavaScript resources as internal or external based on their domain.
- Outputs detailed and summary reports in JSON format.

### How it achieves this:
- Uses Selenium to automate browser interactions and capture network logs.
- Parses network logs to identify JavaScript resources.
- Compares resource domains with the main site domain and a user-provided list of internal domains.
- Supports parallel processing for faster analysis of multiple URLs.

## Command-Line Options
The tool provides several command-line options to customize its behavior:

- `url`: The URL of the site to scan.
- `-i, --input-file`: Path to a file containing a list of domains to scan.
- `-d, --domains-file`: Path to a file containing domains to be considered internal.
- `-o, --output-file`: Path to save the results in JSON format.
- `-j, --jobs`: Number of parallel jobs (default: 2).

## Usage Examples

### Scan a single URL
```bash
python main.py https://example.com -o results.json
```
This command scans `https://example.com` and saves the results to `results.json`.

### Scan multiple URLs from a file
```bash
python main.py -i domains.txt -o results.json -j 4
```
This command scans the domains listed in `domains.txt` using 4 parallel jobs and saves the results to `results.json`.

### Specify internal domains
```bash
python main.py -i domains.txt -d internal_domains.txt -o results.json
```
This command uses `internal_domains.txt` to classify JavaScript resources as internal or external.

### Output summary
The tool automatically generates a summary file alongside the main results file. For example, if the output file is `results.json`, the summary will be saved as `results_summary.txt`.

## Notes
- The tool requires a working installation of Selenium and a compatible Chromium WebDriver.
- Use the `-j` option to optimize performance when scanning a large number of domains.
