# File Integrity Checker

A defensive cybersecurity tool that uses SHA-256 hashes to detect files that have been added, modified, or deleted from an authorized folder.

## Objective

File integrity monitoring helps identify unexpected changes in important files. This project creates a baseline snapshot and compares future scans against it.

## Ethical Scope

Use this tool only on folders and systems that you own or have explicit permission to manage. The tool reads files to calculate hashes and does not modify the scanned folder.

## Requirements

- Python 3.8 or later
- No external packages are required

## Project Structure

```text
Task-2-File-Integrity-Checker/
├── integrity_checker.py
├── README.md
└── sample_folder/
    ├── config.txt
    └── welcome.txt
```

## Usage

From this folder, create a baseline:

```bash
python3 integrity_checker.py baseline sample_folder --output baseline.json
```

Compare the folder with the saved baseline:

```bash
python3 integrity_checker.py compare sample_folder --baseline baseline.json
```

The comparison reports:

- **ADDED**: a new file exists now but was not in the baseline.
- **MODIFIED**: a file exists in both scans, but its SHA-256 hash changed.
- **DELETED**: a baseline file is no longer present.

The program exits with status `0` when no changes are detected, `2` when changes are detected, and `1` for an execution error.

## Demonstration

1. Run the baseline command.
2. Edit `sample_folder/welcome.txt`.
3. Create a new file inside `sample_folder`.
4. Delete one of the original files.
5. Run the compare command and review the report.

Example output:

```text
Added: 1 | Modified: 1 | Deleted: 1
ADDED: new_file.txt
MODIFIED: welcome.txt
DELETED: config.txt
STATUS: Changes detected.
```

## Security Notes

SHA-256 is used for integrity comparison, not for password storage. A hash change indicates that file content changed; it does not by itself explain who changed the file or whether the change is malicious. For production monitoring, protect the baseline file from unauthorized modification and store it separately from the monitored folder.

## Internship Deliverables

- Source code: `integrity_checker.py`
- Documentation: `README.md`
- Demo evidence: terminal screenshots or a short screen-recording showing baseline creation, file changes, and the comparison report.
