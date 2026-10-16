# WannaCry Forensic Case Study - Group 35

Cyber Security CA-II | Symbiosis Institute of Technology, Pune

Members: Riddhi Musale (23070123108), Sai Punadikar (23070123111),
Saniya Chatterjee (23070123113), Sunidhi Choubey (23070123137)

## Methodology summary
Qualitative single-case documentary study of the WannaCry ransomware attack (May 2017),
organised by the NIST SP 800-86 phases (collection, examination, analysis, reporting).
Sources: vendor malware analyses, government reports, indictments and threat-intelligence
reports (see the references in the report).

## What this zip contains
- `G35.docx` - the case study report
- `wannacry_forensic_demo.py` - supporting demo of the detection controls in Section 4.6
- `README.md` - this file

## Safety statement
No malware, exploit code or real WannaCry sample is included or used. The script runs on
SYNTHETIC logs only and makes no network connections. The kill-switch domain in the script
is a placeholder.

## How to run
Requires Python 3.8+. No extra libraries.

    python wannacry_forensic_demo.py

On Google Colab: upload the file, then run `!python wannacry_forensic_demo.py`.

## What the script does
1. Hashes a file with SHA-256 (evidence integrity)
2. Calculates the patch gap (14 Mar 2017 patch to 12 May 2017 outbreak = 59 days)
3. Generates synthetic logs and runs four detection rules: SMB scanning on TCP/445,
   service installed from a writable path, mass rename to one extension, kill-switch DNS lookup

## Expected output
Four alerts, all on the simulated infected host PC-09.

## GitHub
Repository link:https://github.com/RiddhiMusale01/wannacry-forensic-case-study-g35
