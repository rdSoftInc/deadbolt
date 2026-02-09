# Web Test Targets

This directory contains web targets used **only for testing and validation**
of Deadbolt’s web reconnaissance and scanning pipeline.

Targets listed here are intentionally chosen to be **public, non-sensitive,
and designed for testing purposes**.


## lab.txt

The file `lab.txt` contains test targets used during development and evaluation
of Deadbolt’s web scanning features.

### Included Target

- **https://postman-echo.com**

### About postman-echo.com

`postman-echo.com` is a public HTTP testing service provided by Postman.  
It is designed to echo requests and validate HTTP clients and tooling.

It is commonly used for:

- API testing
- HTTP request validation
- Tool development and demos

### Usage Notes

- This target is **not a real application**
- It does **not contain sensitive data**
- It is intended for **testing and demonstration only**

Deadbolt uses this endpoint strictly for:

- Connectivity testing
- Request/response validation
- Pipeline verification

## Responsible Use

Do **not** add real production targets or third-party systems unless you have
explicit permission to test them.

Deadbolt is intended for **authorized security testing only**.