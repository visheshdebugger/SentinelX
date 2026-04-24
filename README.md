# SentinelX – Website Security Scanner

SentinelX is a Chrome extension that helps users evaluate website safety before entering passwords, making payments, or downloading files.

It scans websites for phishing signals, suspicious domains, unsafe behavior patterns, redirects, insecure pages, and trust indicators.

---

## Features

- Real-time website trust score
- Detect phishing-style signals
- Suspicious domain analysis
- HTTPS security checks
- Hidden iframe / redirect detection
- Unsafe login page warnings
- Confidence labels (Trusted / Caution / Dangerous)
- Scan history dashboard
- Clean modern popup UI

---

## Why SentinelX?

Many unsafe websites look normal.

SentinelX helps users make smarter browsing decisions in seconds.

Use it before:

- Logging in
- Entering payment info
- Downloading files
- Visiting unknown websites

---

## Installation (Developer Mode)

1. Download or clone this repository
2. Open Chrome and go to:

chrome://extensions/

3. Enable **Developer Mode**
4. Click **Load unpacked**
5. Select the SentinelX project folder

---

## Privacy

SentinelX is designed with privacy in mind.

- No personal data sold
- No password collection
- Local browser-based scanning
- Transparent permissions only

See `privacy-policy.md`

---

## Project Structure

```text
manifest.json
background.js
contentScript.js
popup/
icons/
privacy-policy.md
