# Email-Analyzer
An automated email artifact analysis tool designed to parse .eml files, extract attachments, headers, and embedded URLs, and enrich them with threat intelligence from VirusTotal, URLScan.io, and ScreenshotAPI. Built using Flask and Python, this tool streamlines phishing investigation and enhances email security operations.

# Automated Email Artifact Analyzer

This project provides a lightweight, web-based platform for automating the extraction and enrichment of email artifacts from `.eml` files. It aims to assist security analysts in quickly identifying phishing attempts, malicious attachments, and suspicious URLs.

## 🚀 Features

- Upload `.eml` files through a web interface
- Parse and extract:
  - Sender address, recipient, subject, date, and originating IP
  - Attachment filenames and generate SHA-256 hashes
  - Embedded URLs, including unwrapping URLDefense links
- Threat enrichment:
  - Visual preview of URLs via ScreenshotAPI
  - Reputation checks on URLs using VirusTotal and URLScan.io
  - Direct links for further analysis on external threat platforms
- Full email body display for manual inspection
- Guidance for next-step analysis included

## 🛠️ Built With

- [Flask](https://flask.palletsprojects.com/) – Web application framework
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) – HTML parsing
- [VirusTotal API](https://docs.virustotal.com/reference)
- [URLScan.io API](https://urlscan.io/docs/api/)
- [ScreenshotAPI](https://www.screenshotapi.net/)

## 📷 Screenshots

| Upload Page | Parsed Results | URL Visual Preview |
|:-----------:|:--------------:|:------------------:|
| ![Upload Page](screenshots/upload_page.png) | ![Parsed Results](screenshots/parsed_results.png) | ![URL Preview](screenshots/url_preview.png) |

_(Make sure to add your screenshots inside a `/screenshots/` folder!)_

## 🏁 Getting Started

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/automated-email-artifact-analyzer.git
   cd automated-email-artifact-analyzer
