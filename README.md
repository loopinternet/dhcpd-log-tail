# DHCP Log Tail and Analysis

A high-performance DHCP log monitoring and analysis system that parses ISC DHCP server logs, stores events in SQLite, and provides fast querying capabilities.

## Features

- **Real-time log tailing** with automatic rotation detection
- **Bulk import** of historical log files with optimized performance
- **Comprehensive parsing** of DHCP events (DISCOVER, OFFER, REQUEST, ACK, NAK, etc.)
- **Duplicate prevention** across restarts and log rotations
- **Fast queries** for MAC/IP tracking and lease analysis
- **High performance**: 27K+ events/sec processing rate

## Quick Start

### 1. Build the binaries

```bash
go build -o dhcp-tail main.go
go build -o dhcp-query query.go
```

### 2. Normal usage (real-time monitoring)

```bash
# Start monitoring with defaults (shown here explicitly for clarity)
./dhcp-tail -logDir=/var/log -logPrefix=dhcpd -dbFile=dhcp.db -initialScan=true
```

### 3. Large initial import (recommended for first-time setup)

```bash
# Bulk import all historical logs (much faster)
./dhcp-tail \
  -logDir=/var/log \
  -logPrefix=dhcpd \
  -dbFile=dhcp.db \
  -initialScan=true \
  -processAllFiles=true \
  -noTail=true \
  -batchSize=15000 \
  -bulkOptimize=true

# Then start normal monitoring
./dhcp-tail -logDir=/var/log -logPrefix=dhcpd -dbFile=dhcp.db
```

## Querying

```bash
# Find last activity for a MAC address
./dhcp-query -db=dhcp.db -mac="aa:bb:cc:dd:ee:ff"

# Find last lease for an IP address  
./dhcp-query -db=dhcp.db -ip="192.168.1.100"

# Show denied leases
./dhcp-query -db=dhcp.db -denied -limit=20

# Database statistics
./dhcp-query -db=dhcp.db -count
```

## Configuration Options

### Key Flags

- `-logDir`: Directory containing DHCP log files (default: `/var/log`)
- `-logPrefix`: Log file prefix (default: `dhcpd`)
- `-dbFile`: SQLite database path (default: `dhcp.db`)
- `-initialScan`: Process existing log entries on startup
- `-processAllFiles`: Process all rotated log files (not just current)
- `-noTail`: Exit after import (don't monitor for new entries)
- `-batchSize`: Events per database batch (default: `2000`, use `15000` for bulk import)
- `-bulkOptimize`: Enable aggressive pragmas for faster bulk inserts

### Performance Tuning

For **large datasets** (>1GB logs):
- Use `-batchSize=15000` 
- Enable `-bulkOptimize=true`
- Process with `-noTail=true` first, then start normal monitoring

For **normal monitoring**:
- Default settings work well
