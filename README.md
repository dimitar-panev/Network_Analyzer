# Network Analyzer

A minimal, modern web UI with essential tools for network engineers.

Tools included:
- Ping
- Traceroute
- DNS Lookup
- WHOIS
- Port Scanner
- HTTP tester
- SSL/TLS info
- Subnet calculator
- Interfaces
- ARP table
- Speedtest (speedtest.net via speedtest-cli)

## Setup

1. Create and activate a virtual environment (recommended)
   
   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   ```

2. Install dependencies
   
   ```bash
   pip install -r requirements.txt
   ```

3. Run
   
   ```bash
   python run.py
   # or specify a port
   PORT=5050 python run.py
   ```

Open http://localhost:5000 in your browser. If 5000 is taken, the app now auto-selects a nearby free port and prints it, e.g. http://localhost:5001.

## Notes
- Some tools rely on system commands (ping, traceroute/tracert, ip). Ensure they are installed and allowed.
- Port scanner is basic TCP connect scan. Use responsibly on networks you own or have permission to test.
- WHOIS depends on python-whois; TLD coverage varies.
- Speedtest uses the public speedtest.net infrastructure; results depend on server selection and may consume bandwidth.

### Troubleshooting
- Port already in use: find and kill the process using it:
  ```bash
  lsof -i :5000
  kill -9 <PID>
  ```
- Or simply use a different port: `PORT=5050 python run.py`.
- For the moments the application is not hosted properly since it hosts itself through run.py. Until I host the application somewhere else, I will be working this way. That means that if you want to test the application you will have to download the whole repo.
