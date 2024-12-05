# Log Analysis Tool

## Overview

The **Log Analysis Tool** is a Python-based script that parses web server log files to extract key insights such as:

- The number of requests made by each IP address.
- The most frequently accessed endpoint.
- Suspicious activity detection for potential brute-force login attempts.

This tool is intended to help server administrators and security teams analyze web traffic and identify unusual patterns that may indicate malicious behavior.

---

## Features

### 1. Request Count per IP Address
- Parse the provided log file to extract and count the number of requests made by each unique IP address.
- Display the results in descending order of request counts.

### 2. Most Frequently Accessed Endpoint
- Identify the endpoint (e.g., URLs or resource paths) that has been accessed the most.

### 3. Suspicious Activity Detection
- Detect potential brute-force login attempts by looking for failed login attempts (e.g., HTTP status code `401` or failure messages like "Invalid credentials").
- Flag IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).

### 4. CSV Output
- Results are saved in `log_analysis_results.csv` with sections for:
  - **Requests per IP**
  - **Most Accessed Endpoint**
  - **Suspicious Activity** (if any)

---

## Installation

### Prerequisites
- Python 3.x or higher

### Setup Instructions
1. **Clone the repository:**
   ```bash
   git clone https://github.com/byleenjanetroy/log-analysis.git

2. **Navigate to the project directory:**
cd log-analysis
 
3. **Install dependencies (if a requirements.txt exists):**
pip install -r requirements.txt
Ensure the log file (e.g., access.log) is available for analysis.

4. **Running the Script**
To analyze a log file, run the following command in the terminal:
python log_analysis.py
