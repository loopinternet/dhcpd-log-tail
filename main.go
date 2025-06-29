package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

// DHCPEvent represents a parsed DHCP log entry
type DHCPEvent struct {
	ID          int64
	Timestamp   time.Time
	MACAddress  string
	IPAddress   string
	MessageType string
	RelayIP     string
	NetworkName string
	Hostname    string
	Reason      string
	RequestedIP string
	ServerIP    string
	LeaseAge    int
	RawMessage  string
	CreatedAt   time.Time
}

// Configuration flags
var (
	logDir         = flag.String("logDir", "/var/log", "directory containing DHCP log files")
	logPrefix      = flag.String("logPrefix", "dhcpd", "prefix of DHCP log files")
	dbFile         = flag.String("dbFile", "dhcp.db", "SQLite database file path")
	logLevel       = flag.String("logLevel", "info", "log level can be trace, debug, info, warn, or error")
	logTimestamp   = flag.Bool("logTimestamp", true, "show timestamp in logs")
	initialScan    = flag.Bool("initialScan", true, "scan existing log files on startup")
	pollInterval   = flag.Duration("pollInterval", 1*time.Second, "interval for polling log file changes")
	batchSize      = flag.Int("batchSize", 2000, "number of events to batch for database insertion")
	bulkOptimize   = flag.Bool("bulkOptimize", false, "enable bulk import optimizations (aggressive pragma settings for faster inserts)")
	processAllFiles = flag.Bool("processAllFiles", false, "process all matching log files (including rotated logs) during initial scan")
	noTail          = flag.Bool("noTail", false, "exit after initial import instead of tailing the log file")
)

// FileState tracks the state of a log file for rotation detection
type FileState struct {
	Size  int64
	Inode uint64
	Mtime time.Time
}

// FileTailer manages tailing a log file with rotation detection
type FileTailer struct {
	filename        string
	file            *os.File
	reader          *bufio.Reader
	state           FileState
	position        int64
	initialPosition int64  // Position when file was first opened (for initial scan boundary)
	db              *sql.DB
	pollInterval    time.Duration
}

// NewFileTailer creates a new file tailer
func NewFileTailer(filename string, db *sql.DB, pollInterval time.Duration) *FileTailer {
	return &FileTailer{
		filename:     filename,
		db:           db,
		pollInterval: pollInterval,
	}
}

// getFileState returns the current state of the file
func (ft *FileTailer) getFileState() (FileState, error) {
	info, err := os.Stat(ft.filename)
	if err != nil {
		return FileState{}, err
	}

	stat := info.Sys().(*syscall.Stat_t)
	return FileState{
		Size:  info.Size(),
		Inode: stat.Ino,
		Mtime: info.ModTime(),
	}, nil
}

// openFile opens the log file and positions at the end
func (ft *FileTailer) openFile() error {
	file, err := os.Open(ft.filename)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", ft.filename, err)
	}

	ft.file = file
	ft.reader = bufio.NewReader(file)
	
	// Position at end of file for tailing
	ft.position, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to seek to end of file: %w", err)
	}

	// Record initial position - this is where we'll start tailing from after initial scan
	// This prevents race conditions where entries are added during initial scan
	ft.initialPosition = ft.position

	// Update file state
	ft.state, err = ft.getFileState()
	if err != nil {
		return fmt.Errorf("failed to get file state: %w", err)
	}

	log.Debugf("Opened file %s, size: %d, initial position: %d", ft.filename, ft.state.Size, ft.initialPosition)
	return nil
}

// hasRotated checks if the file has been rotated
func (ft *FileTailer) hasRotated() (bool, error) {
	currentState, err := ft.getFileState()
	if err != nil {
		return false, err
	}

	// File has been rotated if:
	// 1. Size is smaller than our current position (file was truncated/replaced)
	// 2. Inode changed (file was moved and recreated)
	rotated := currentState.Size < ft.position || currentState.Inode != ft.state.Inode

	if rotated {
		log.Infof("File rotation detected: size changed from %d to %d, inode changed from %d to %d",
			ft.state.Size, currentState.Size, ft.state.Inode, currentState.Inode)
	}

	return rotated, nil
}

// reopenFile handles file rotation by closing current file and opening new one
func (ft *FileTailer) reopenFile() error {
	if ft.file != nil {
		ft.file.Close()
	}

	log.Info("Reopening file after rotation")
	err := ft.openFile()
	if err != nil {
		return err
	}
	
	// After rotation, we start tailing from the beginning of the new file
	// (openFile already positioned us at the end and set initialPosition)
	ft.position = 0
	_, err = ft.file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start after rotation: %w", err)
	}
	
	// Recreate reader
	ft.reader = bufio.NewReader(ft.file)
	
	return nil
}

// processLine parses a log line and inserts it into the database
func (ft *FileTailer) processLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	event, err := parseDHCPLine(line)
	if err != nil {
		log.Debugf("Failed to parse line: %v - %s", err, line)
		return
	}

	// Check if event already exists to prevent duplicates during real-time tailing
	exists, err := eventExists(ft.db, event)
	if err != nil {
		log.Errorf("Failed to check event existence: %v", err)
		return
	}
	
	if exists {
		log.Debugf("Skipping duplicate event: %s - %s", event.MessageType, event.MACAddress)
		return
	}

	if err := insertEvent(ft.db, event); err != nil {
		log.Errorf("Failed to insert event: %v", err)
		return
	}

	log.Debugf("Inserted event: %s - %s", event.MessageType, event.MACAddress)
}

// scanExistingFile scans the file from beginning up to the initial position
func (ft *FileTailer) scanExistingFile(cutoffTime time.Time) error {
	log.Info("Scanning existing log file...")
	
	// Initialize performance tracking
	stats := NewPerformanceStats()
	defer stats.Report()
	
	if !cutoffTime.IsZero() {
		log.Infof("Skipping entries older than or equal to: %s", cutoffTime.Format("2006-01-02 15:04:05"))
	}
	
	// Enable bulk import optimizations if requested
	var bulkMode bool
	if *bulkOptimize {
		bulkMode = true
		log.Info("Enabling bulk import optimizations...")
		
		if err := setBulkImportPragmas(ft.db); err != nil {
			log.Warnf("Failed to set bulk pragmas: %v", err)
			bulkMode = false
		} else {
			log.Info("Bulk import pragmas enabled")
		}
	}
	
	// Restore normal settings when done
	defer func() {
		if bulkMode {
			log.Info("Restoring normal database settings...")
			if err := setNormalPragmas(ft.db); err != nil {
				log.Errorf("Failed to restore normal pragmas: %v", err)
			} else {
				log.Info("Normal pragmas restored")
			}
		}
	}()
	
	// Seek to beginning
	_, err := ft.file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start of file: %w", err)
	}

	// Create a limited reader that only reads up to initialPosition
	// This prevents reading entries that were added during the scan
	limitedReader := io.LimitReader(ft.file, ft.initialPosition)
	scanner := bufio.NewScanner(limitedReader)
	
	// Increase scanner buffer size for better performance with large files
	buf := make([]byte, 64*1024) // 64KB buffer
	scanner.Buffer(buf, 1024*1024) // 1MB max token size
	
	var eventBatch []*DHCPEvent
	lastProgressReport := time.Now()
	
	for scanner.Scan() {
		line := scanner.Text()
		stats.LinesRead++
		
		if strings.TrimSpace(line) == "" {
			stats.LinesSkipped++
			continue
		}

		// Parse line with timing
		parseStart := time.Now()
		event, err := parseDHCPLine(line)
		stats.ParseTime += time.Since(parseStart)
		
		if err != nil {
			log.Debugf("Failed to parse line %d: %v", stats.LinesRead, err)
			stats.LinesSkipped++
			continue
		}
		
		stats.EventsParsed++

		// Skip entries that are older than or equal to the cutoff time
		if !cutoffTime.IsZero() && (event.Timestamp.Before(cutoffTime) || event.Timestamp.Equal(cutoffTime)) {
			stats.EventsDuplicate++
			continue
		}

		// Add to batch
		eventBatch = append(eventBatch, event)
		
		// Insert batch when it reaches batch size
		if len(eventBatch) >= *batchSize {
			insertStart := time.Now()
			
			var insertErr error
			if bulkMode {
				insertErr = insertEventsBatchOptimized(ft.db, eventBatch)
			} else {
				insertErr = insertEventsBatch(ft.db, eventBatch)
			}
			
			if insertErr != nil {
				log.Errorf("Failed to insert batch: %v", insertErr)
				// Continue processing, don't fail completely
			} else {
				stats.EventsInserted += int64(len(eventBatch))
			}
			stats.InsertTime += time.Since(insertStart)
			eventBatch = eventBatch[:0] // Reset batch
		}

		// Progress reporting every 5 seconds
		if time.Since(lastProgressReport) >= 5*time.Second {
			elapsed := time.Since(stats.StartTime)
			linesPerSec := float64(stats.LinesRead) / elapsed.Seconds()
			eventsPerSec := float64(stats.EventsInserted) / elapsed.Seconds()
			
			mode := "normal"
			if bulkMode {
				mode = "optimized"
			}
			
			log.Infof("Progress (%s): %d lines (%.0f/sec), %d events inserted (%.0f/sec), %d duplicates", 
				mode, stats.LinesRead, linesPerSec, stats.EventsInserted, eventsPerSec, stats.EventsDuplicate)
			lastProgressReport = time.Now()
		}
	}

	// Insert any remaining events in the final batch
	if len(eventBatch) > 0 {
		insertStart := time.Now()
		
		var insertErr error
		if bulkMode {
			insertErr = insertEventsBatchOptimized(ft.db, eventBatch)
		} else {
			insertErr = insertEventsBatch(ft.db, eventBatch)
		}
		
		if insertErr != nil {
			log.Errorf("Failed to insert final batch: %v", insertErr)
		} else {
			stats.EventsInserted += int64(len(eventBatch))
		}
		stats.InsertTime += time.Since(insertStart)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	log.Infof("Completed initial scan: processed %d lines, inserted %d events, skipped %d duplicates", 
		stats.LinesRead, stats.EventsInserted, stats.EventsDuplicate)

	// Position at initial position for tailing (not current end, to avoid race condition)
	ft.position, err = ft.file.Seek(ft.initialPosition, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to initial position after scan: %w", err)
	}

	// Recreate reader since we've been seeking around
	ft.reader = bufio.NewReader(ft.file)

	return nil
}

// tail starts tailing the log file
func (ft *FileTailer) tail() error {
	log.Infof("Starting to tail log file: %s", ft.filename)

	if err := ft.openFile(); err != nil {
		return err
	}
	defer ft.file.Close()

	// Perform initial scan if requested
	if *initialScan {
		// Get the latest timestamp from database to avoid re-ingesting old entries
		cutoffTime, err := getLatestTimestamp(ft.db)
		if err != nil {
			return fmt.Errorf("failed to get latest timestamp: %w", err)
		}
		
		if !cutoffTime.IsZero() {
			log.Infof("Database contains entries up to: %s", cutoffTime.Format("2006-01-02 15:04:05"))
			
			// Check if we can skip this entire file
			shouldSkip, err := shouldSkipFile(ft.filename, cutoffTime)
			if err != nil {
				log.Warnf("Error checking if file should be skipped: %v", err)
			} else if shouldSkip {
				log.Infof("Skipping initial scan - file is entirely older than database")
				// Position at end for tailing
				ft.position, err = ft.file.Seek(ft.initialPosition, io.SeekStart)
				if err != nil {
					return fmt.Errorf("failed to seek to initial position: %w", err)
				}
				ft.reader = bufio.NewReader(ft.file)
				return nil // Skip the scan but continue to tailing
			}
		} else {
			log.Info("Database is empty, will process all entries")
		}
		
		if err := ft.scanExistingFile(cutoffTime); err != nil {
			return fmt.Errorf("initial scan failed: %w", err)
		}
	}

	ticker := time.NewTicker(ft.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check for file rotation
			rotated, err := ft.hasRotated()
			if err != nil {
				log.Errorf("Failed to check for rotation: %v", err)
				continue
			}

			if rotated {
				if err := ft.reopenFile(); err != nil {
					log.Errorf("Failed to reopen file after rotation: %v", err)
					continue
				}
			}

			// Read new lines
			for {
				line, isPrefix, err := ft.reader.ReadLine()
				if err != nil {
					if err == io.EOF {
						break // No more data available
					}
					log.Errorf("Error reading line: %v", err)
					break
				}

				// Handle partial lines (lines longer than buffer)
				if isPrefix {
					// Continue reading until we get the complete line
					continue
				}

				ft.processLine(string(line))
				
				// Update position
				currentPos, err := ft.file.Seek(0, io.SeekCurrent)
				if err == nil {
					ft.position = currentPos
				}
			}

			// Update file state
			if newState, err := ft.getFileState(); err == nil {
				ft.state = newState
			}
		}
	}
}

// Regex patterns for parsing DHCP log entries
var (
	// General log line pattern: timestamp hostname process[pid]: message
	logLinePattern = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+dhcpd\[\d+\]:\s+(.+)$`)
	
	// DHCP message patterns
	discoverPattern = regexp.MustCompile(`^DHCPDISCOVER from ([0-9a-f:]{17}) via ([0-9a-zA-Z.]+)(?:: (?:network ([^:]+): (.+)|(.+)))?$`)
	requestPattern  = regexp.MustCompile(`^DHCPREQUEST for ([0-9.]+)(?: \(([0-9.]+)\))? from ([0-9a-f:]{17})(?: \(([^)]+)\))? via ([0-9a-zA-Z.]+)(?:: (.+))?$`)
	offerPattern    = regexp.MustCompile(`^DHCPOFFER on ([0-9.]+) to ([0-9a-f:]{17}) via ([0-9a-zA-Z.]+)$`)
	ackPattern      = regexp.MustCompile(`^DHCPACK on ([0-9.]+) to ([0-9a-f:]{17})(?: \(([^)]+)\))? via ([0-9a-zA-Z.]+)$`)
	nakPattern      = regexp.MustCompile(`^DHCPNAK on ([0-9.]+) to ([0-9a-f:]{17}) via ([0-9a-zA-Z.]+)$`)
	reusePattern    = regexp.MustCompile(`^reuse_lease: lease age (\d+) \(secs\) under 25% threshold, reply with unaltered, existing lease for ([0-9.]+)$`)
	
	// Administrative messages
	leaseWritePattern = regexp.MustCompile(`^Wrote (\d+) (?:deleted host decls|new dynamic host decls|leases) to leases file\.$`)
)

// Database setup
func initDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set SQLite performance optimizations for bulk inserts
	pragmas := []string{
		"PRAGMA synchronous = NORMAL",     // Balance safety and performance
		"PRAGMA cache_size = 10000",       // 10MB cache
		"PRAGMA temp_store = memory",      // Store temp tables in memory
		"PRAGMA journal_mode = WAL",       // Write-Ahead Logging for better concurrency
		"PRAGMA busy_timeout = 30000",     // 30 second busy timeout
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			log.Warnf("Failed to set pragma %s: %v", pragma, err)
		}
	}

	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS dhcp_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		mac_address TEXT,
		ip_address TEXT,
		message_type TEXT NOT NULL,
		relay_ip TEXT,
		network_name TEXT,
		hostname TEXT,
		reason TEXT,
		requested_ip TEXT,
		server_ip TEXT,
		lease_age INTEGER,
		raw_message TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_mac_address ON dhcp_events(mac_address);
	CREATE INDEX IF NOT EXISTS idx_ip_address ON dhcp_events(ip_address);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON dhcp_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_message_type ON dhcp_events(message_type);
	CREATE INDEX IF NOT EXISTS idx_mac_timestamp ON dhcp_events(mac_address, timestamp);
	CREATE INDEX IF NOT EXISTS idx_ip_timestamp ON dhcp_events(ip_address, timestamp);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	log.Info("Database initialized successfully")
	return db, nil
}

// Parse DHCP log line
func parseDHCPLine(line string) (*DHCPEvent, error) {
	matches := logLinePattern.FindStringSubmatch(line)
	if len(matches) != 3 {
		return nil, fmt.Errorf("invalid log line format")
	}

	timestampStr := matches[1]
	message := matches[2]

	// Parse timestamp (assume current year)
	currentYear := time.Now().Year()
	timestamp, err := time.Parse("Jan 2 15:04:05", timestampStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}
	timestamp = timestamp.AddDate(currentYear, 0, 0)

	event := &DHCPEvent{
		Timestamp:  timestamp,
		RawMessage: line,
		CreatedAt:  time.Now(),
	}

	// Parse different message types
	if matches := discoverPattern.FindStringSubmatch(message); matches != nil {
		event.MessageType = "DISCOVER"
		event.MACAddress = matches[1]
		event.RelayIP = matches[2]
		if len(matches) > 3 && matches[3] != "" {
			// Format: "network X: reason"
			event.NetworkName = matches[3]
			event.Reason = matches[4]
		} else if len(matches) > 5 && matches[5] != "" {
			// Format: "reason" (without network prefix)
			event.Reason = matches[5]
		}
	} else if matches := requestPattern.FindStringSubmatch(message); matches != nil {
		event.MessageType = "REQUEST"
		event.RequestedIP = matches[1]
		if matches[2] != "" {
			event.ServerIP = matches[2]
		}
		event.MACAddress = matches[3]
		if matches[4] != "" {
			event.Hostname = matches[4]
		}
		event.RelayIP = matches[5]
		if len(matches) > 6 && matches[6] != "" {
			event.Reason = matches[6]
		}
	} else if matches := offerPattern.FindStringSubmatch(message); matches != nil {
		event.MessageType = "OFFER"
		event.IPAddress = matches[1]
		event.MACAddress = matches[2]
		event.RelayIP = matches[3]
	} else if matches := ackPattern.FindStringSubmatch(message); matches != nil {
		event.MessageType = "ACK"
		event.IPAddress = matches[1]
		event.MACAddress = matches[2]
		if matches[3] != "" {
			event.Hostname = matches[3]
		}
		event.RelayIP = matches[4]
	} else if matches := nakPattern.FindStringSubmatch(message); matches != nil {
		event.MessageType = "NAK"
		event.IPAddress = matches[1]
		event.MACAddress = matches[2]
		event.RelayIP = matches[3]
	} else if matches := reusePattern.FindStringSubmatch(message); matches != nil {
		event.MessageType = "REUSE_LEASE"
		event.LeaseAge = parseInt(matches[1])
		event.IPAddress = matches[2]
	} else if matches := leaseWritePattern.FindStringSubmatch(message); matches != nil {
		event.MessageType = "LEASE_FILE_WRITE"
		event.LeaseAge = parseInt(matches[1]) // Reuse this field to store count
		event.Reason = message // Store full message in reason field
	} else {
		return nil, fmt.Errorf("unknown message format: %s", message)
	}

	return event, nil
}

// Helper function to parse integer
func parseInt(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

// Insert event into database
func insertEvent(db *sql.DB, event *DHCPEvent) error {
	query := `
	INSERT INTO dhcp_events (
		timestamp, mac_address, ip_address, message_type, relay_ip,
		network_name, hostname, reason, requested_ip, server_ip,
		lease_age, raw_message, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
		event.Timestamp,
		event.MACAddress,
		event.IPAddress,
		event.MessageType,
		event.RelayIP,
		event.NetworkName,
		event.Hostname,
		event.Reason,
		event.RequestedIP,
		event.ServerIP,
		event.LeaseAge,
		event.RawMessage,
		event.CreatedAt,
	)

	return err
}

// insertEventsBatch inserts multiple events in a single transaction for better performance
func insertEventsBatch(db *sql.DB, events []*DHCPEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
	INSERT INTO dhcp_events (
		timestamp, mac_address, ip_address, message_type, relay_ip,
		network_name, hostname, reason, requested_ip, server_ip,
		lease_age, raw_message, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		_, err := stmt.Exec(
			event.Timestamp,
			event.MACAddress,
			event.IPAddress,
			event.MessageType,
			event.RelayIP,
			event.NetworkName,
			event.Hostname,
			event.Reason,
			event.RequestedIP,
			event.ServerIP,
			event.LeaseAge,
			event.RawMessage,
			event.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// insertEventsBatchOptimized uses multi-row INSERT for maximum performance
func insertEventsBatchOptimized(db *sql.DB, events []*DHCPEvent) error {
	if len(events) == 0 {
		return nil
	}

	// SQLite has a default limit of 999 variables per statement
	// With 13 columns per event, we can safely insert ~76 events per statement
	const maxEventsPerStatement = 75 // Conservative limit
	
	// Process events in chunks
	for i := 0; i < len(events); i += maxEventsPerStatement {
		end := i + maxEventsPerStatement
		if end > len(events) {
			end = len(events)
		}
		
		chunk := events[i:end]
		if err := insertChunkOptimized(db, chunk); err != nil {
			return fmt.Errorf("failed to insert chunk %d-%d: %w", i, end-1, err)
		}
	}

	return nil
}

// insertChunkOptimized inserts a small chunk of events using multi-row INSERT
func insertChunkOptimized(db *sql.DB, events []*DHCPEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Build multi-row INSERT statement
	baseQuery := `INSERT INTO dhcp_events (
		timestamp, mac_address, ip_address, message_type, relay_ip,
		network_name, hostname, reason, requested_ip, server_ip,
		lease_age, raw_message, created_at
	) VALUES `
	
	// Create value placeholders
	valueStrings := make([]string, 0, len(events))
	valueArgs := make([]interface{}, 0, len(events)*13)
	
	for _, event := range events {
		valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		valueArgs = append(valueArgs,
			event.Timestamp,
			event.MACAddress,
			event.IPAddress,
			event.MessageType,
			event.RelayIP,
			event.NetworkName,
			event.Hostname,
			event.Reason,
			event.RequestedIP,
			event.ServerIP,
			event.LeaseAge,
			event.RawMessage,
			event.CreatedAt,
		)
	}

	// Execute the multi-row insert
	query := baseQuery + strings.Join(valueStrings, ",")
	_, err := db.Exec(query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to execute multi-row insert: %w", err)
	}

	return nil
}



// setBulkImportPragmas sets aggressive SQLite settings for bulk imports
func setBulkImportPragmas(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA synchronous = OFF",        // Disable sync for maximum speed
		"PRAGMA journal_mode = MEMORY",    // Keep journal in memory
		"PRAGMA cache_size = 50000",       // 50MB cache
		"PRAGMA temp_store = memory",      // Temp tables in memory
		"PRAGMA mmap_size = 268435456",    // 256MB mmap
		"PRAGMA optimize",                 // Let SQLite optimize
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			log.Warnf("Failed to set pragma %s: %v", pragma, err)
		}
	}

	log.Info("Bulk import pragmas enabled")
	return nil
}

// setNormalPragmas restores normal SQLite settings after bulk import
func setNormalPragmas(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA synchronous = NORMAL",
		"PRAGMA journal_mode = WAL",
		"PRAGMA cache_size = 10000",
		"PRAGMA optimize",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			log.Warnf("Failed to set pragma %s: %v", pragma, err)
		}
	}

	log.Info("Normal pragmas restored")
	return nil
}

// getLatestTimestamp returns the most recent timestamp from the database
// Returns zero time if no entries exist
func getLatestTimestamp(db *sql.DB) (time.Time, error) {
	query := `SELECT MAX(timestamp) FROM dhcp_events`
	
	var timestampStr sql.NullString
	err := db.QueryRow(query).Scan(&timestampStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query latest timestamp: %w", err)
	}
	
	if !timestampStr.Valid || timestampStr.String == "" {
		// No entries in database yet
		return time.Time{}, nil
	}
	
	// Parse the timestamp string back to time.Time
	// SQLite stores timestamps in RFC3339 format
	timestamp, err := time.Parse(time.RFC3339, timestampStr.String)
	if err != nil {
		// Try alternative parsing formats that might be in the database
		if timestamp, err = time.Parse("2006-01-02 15:04:05-07:00", timestampStr.String); err != nil {
			if timestamp, err = time.Parse("2006-01-02 15:04:05+00:00", timestampStr.String); err != nil {
				if timestamp, err = time.Parse("2006-01-02 15:04:05", timestampStr.String); err != nil {
					if timestamp, err = time.Parse("2006-01-02T15:04:05Z", timestampStr.String); err != nil {
						return time.Time{}, fmt.Errorf("failed to parse timestamp %s: %w", timestampStr.String, err)
					}
				}
			}
		}
	}
	
	return timestamp, nil
}

// eventExists checks if an event with the same timestamp and raw message already exists
func eventExists(db *sql.DB, event *DHCPEvent) (bool, error) {
	// Use timestamp string comparison for SQLite compatibility
	query := `SELECT COUNT(*) FROM dhcp_events WHERE datetime(timestamp) = datetime(?) AND raw_message = ?`
	
	var count int
	err := db.QueryRow(query, event.Timestamp.Format(time.RFC3339), event.RawMessage).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check event existence: %w", err)
	}
	
	return count > 0, nil
}

// Query functions have been moved to query.go for the separate query binary

// Helper function to scan DHCPEvent from sql.Row
func scanDHCPEvent(row *sql.Row) (*DHCPEvent, error) {
	event := &DHCPEvent{}
	err := row.Scan(
		&event.ID,
		&event.Timestamp,
		&event.MACAddress,
		&event.IPAddress,
		&event.MessageType,
		&event.RelayIP,
		&event.NetworkName,
		&event.Hostname,
		&event.Reason,
		&event.RequestedIP,
		&event.ServerIP,
		&event.LeaseAge,
		&event.RawMessage,
		&event.CreatedAt,
	)
	return event, err
}

// Helper function to scan DHCPEvent from sql.Rows
func scanDHCPEventFromRows(rows *sql.Rows) (*DHCPEvent, error) {
	event := &DHCPEvent{}
	err := rows.Scan(
		&event.ID,
		&event.Timestamp,
		&event.MACAddress,
		&event.IPAddress,
		&event.MessageType,
		&event.RelayIP,
		&event.NetworkName,
		&event.Hostname,
		&event.Reason,
		&event.RequestedIP,
		&event.ServerIP,
		&event.LeaseAge,
		&event.RawMessage,
		&event.CreatedAt,
	)
	return event, err
}

// Find current log file
func findCurrentLogFile(logDir, prefix string) (string, error) {
	// Look for the current log file (without rotation suffix)
	currentFile := filepath.Join(logDir, prefix+".log")
	if _, err := os.Stat(currentFile); err == nil {
		return currentFile, nil
	}

	// If not found, look for the most recent rotated file
	pattern := filepath.Join(logDir, prefix+"*.log*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("no log files found matching pattern %s", pattern)
	}

	// Return the first match for now (could be improved to find the most recent)
	return matches[0], nil
}

// findAllLogFiles finds all log files matching the pattern, sorted by modification time
func findAllLogFiles(logDir, prefix string) ([]string, error) {
	pattern := filepath.Join(logDir, prefix+"*.log*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no log files found matching pattern %s", pattern)
	}

	// Sort files by modification time (oldest first for chronological processing)
	type fileInfo struct {
		path    string
		modTime time.Time
	}

	var files []fileInfo
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			log.Warnf("Could not stat file %s: %v", match, err)
			continue
		}
		files = append(files, fileInfo{path: match, modTime: info.ModTime()})
	}

	// Sort by modification time (oldest first)
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[i].modTime.After(files[j].modTime) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	result := make([]string, len(files))
	for i, file := range files {
		result[i] = file.path
	}

	return result, nil
}

// processMultipleFiles processes multiple log files with file skipping optimization
func processMultipleFiles(db *sql.DB, logFiles []string) error {
	// Get cutoff time once for all files
	cutoffTime, err := getLatestTimestamp(db)
	if err != nil {
		return fmt.Errorf("failed to get latest timestamp: %w", err)
	}

	if !cutoffTime.IsZero() {
		log.Infof("Database contains entries up to: %s", cutoffTime.Format("2006-01-02 15:04:05"))
	} else {
		log.Info("Database is empty, will process all files")
	}

	processedFiles := 0
	skippedFiles := 0

	for _, logFile := range logFiles {
		log.Infof("Checking log file: %s", logFile)

		// Check if we can skip this entire file
		shouldSkip, err := shouldSkipFile(logFile, cutoffTime)
		if err != nil {
			log.Warnf("Error checking if file should be skipped: %v", err)
		} else if shouldSkip {
			skippedFiles++
			continue
		}

		// Process this file
		tailer := NewFileTailer(logFile, db, time.Second)
		if err := tailer.openFile(); err != nil {
			log.Errorf("Failed to open file %s: %v", logFile, err)
			continue
		}

		if err := tailer.scanExistingFile(cutoffTime); err != nil {
			log.Errorf("Failed to scan file %s: %v", logFile, err)
			tailer.file.Close()
			continue
		}

		tailer.file.Close()
		processedFiles++
	}

	log.Infof("Bulk import complete: processed %d files, skipped %d files", processedFiles, skippedFiles)
	return nil
}

// PerformanceStats tracks performance metrics
type PerformanceStats struct {
	StartTime     time.Time
	LinesRead     int64
	LinesSkipped  int64
	EventsParsed  int64
	EventsInserted int64
	EventsDuplicate int64
	ParseTime     time.Duration
	InsertTime    time.Duration
	TotalTime     time.Duration
}

// NewPerformanceStats creates a new performance stats tracker
func NewPerformanceStats() *PerformanceStats {
	return &PerformanceStats{
		StartTime: time.Now(),
	}
}

// Report prints a performance summary
func (ps *PerformanceStats) Report() {
	ps.TotalTime = time.Since(ps.StartTime)
	
	linesPerSec := float64(ps.LinesRead) / ps.TotalTime.Seconds()
	eventsPerSec := float64(ps.EventsInserted) / ps.TotalTime.Seconds()
	
	log.Infof("Performance Summary:")
	log.Infof("  Total time: %v", ps.TotalTime)
	log.Infof("  Lines read: %d (%.1f lines/sec)", ps.LinesRead, linesPerSec)
	log.Infof("  Lines skipped: %d", ps.LinesSkipped)
	log.Infof("  Events parsed: %d", ps.EventsParsed)
	log.Infof("  Events inserted: %d (%.1f events/sec)", ps.EventsInserted, eventsPerSec)
	log.Infof("  Events duplicate: %d", ps.EventsDuplicate)
	log.Infof("  Parse time: %v (%.1f%%)", ps.ParseTime, ps.ParseTime.Seconds()/ps.TotalTime.Seconds()*100)
	log.Infof("  Insert time: %v (%.1f%%)", ps.InsertTime, ps.InsertTime.Seconds()/ps.TotalTime.Seconds()*100)
}

// getLastTimestampFromFile reads the last valid log entry from a file to get its timestamp
func getLastTimestampFromFile(filename string) (time.Time, error) {
	file, err := os.Open(filename)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to stat file: %w", err)
	}
	
	fileSize := stat.Size()
	if fileSize == 0 {
		return time.Time{}, fmt.Errorf("file is empty")
	}

	// Read backwards from end of file to find last valid log entry
	// Start reading from near the end (last 1KB should be enough for a few log lines)
	bufferSize := int64(1024)
	if bufferSize > fileSize {
		bufferSize = fileSize
	}

	buffer := make([]byte, bufferSize)
	offset := fileSize - bufferSize
	
	_, err = file.ReadAt(buffer, offset)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read from file: %w", err)
	}

	// Split into lines and process from the end
	lines := strings.Split(string(buffer), "\n")
	
	// Process lines in reverse order to find the last valid entry
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Try to parse this line as a DHCP log entry
		event, err := parseDHCPLine(line)
		if err != nil {
			continue // Skip invalid lines
		}

		return event.Timestamp, nil
	}

	return time.Time{}, fmt.Errorf("no valid log entries found in file")
}

// shouldSkipFile determines if a file can be skipped based on its last timestamp
func shouldSkipFile(filename string, cutoffTime time.Time) (bool, error) {
	if cutoffTime.IsZero() {
		return false, nil // No cutoff time, don't skip
	}

	lastTimestamp, err := getLastTimestampFromFile(filename)
	if err != nil {
		log.Warnf("Could not get last timestamp from %s: %v, will process file", filename, err)
		return false, nil // If we can't determine, err on the side of processing
	}

	// Since we don't have subsecond timestamps, subtract 1 second from cutoff to avoid 
	// skipping events that occurred in the same second but are newer than database entries
	adjustedCutoff := cutoffTime.Add(-1 * time.Second)
	
	// Skip only if the file's newest entry is older than our adjusted cutoff
	shouldSkip := lastTimestamp.Before(adjustedCutoff)
	
	if shouldSkip {
		log.Infof("Skipping file %s: newest entry (%s) is older than database cutoff (%s)", 
			filename, lastTimestamp.Format("2006-01-02 15:04:05"), cutoffTime.Format("2006-01-02 15:04:05"))
	}

	return shouldSkip, nil
}

func main() {
	flag.Parse()

	// Setup logging
	logFormat := &log.TextFormatter{
		FullTimestamp: *logTimestamp,
	}
	log.SetFormatter(logFormat)

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %v", err)
	}
	log.SetLevel(level)
	log.Infof("Log level set to %s", *logLevel)

	// Validate required arguments
	if *logDir == "" || *logPrefix == "" || *dbFile == "" {
		flag.Usage()
		log.Fatal("Must specify logDir, logPrefix, and dbFile")
	}

	// Initialize database
	db, err := initDB(*dbFile)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Handle bulk processing of all files if requested
	if *initialScan && *processAllFiles {
		log.Info("Processing all log files for bulk import...")
		
		allFiles, err := findAllLogFiles(*logDir, *logPrefix)
		if err != nil {
			log.Fatalf("Failed to find log files: %v", err)
		}
		
		log.Infof("Found %d log files to process", len(allFiles))
		for i, file := range allFiles {
			log.Infof("  %d: %s", i+1, file)
		}
		
		if err := processMultipleFiles(db, allFiles); err != nil {
			log.Fatalf("Failed to process multiple files: %v", err)
		}
		
		log.Info("Bulk import completed successfully")
		return
	}

	// Find current log file for single-file processing or tailing
	currentLogFile, err := findCurrentLogFile(*logDir, *logPrefix)
	if err != nil {
		log.Fatalf("Failed to find current log file: %v", err)
	}
	log.Infof("Found current log file: %s", currentLogFile)

	// Create file tailer
	tailer := NewFileTailer(currentLogFile, db, *pollInterval)
	
	log.Info("DHCP log tail program initialized successfully")
	
	// If noTail is set, just do the initial import and exit
	if *noTail {
		if *initialScan {
			log.Info("Performing initial scan and exiting (noTail=true)")
			
			// Open the file for scanning
			if err := tailer.openFile(); err != nil {
				log.Fatalf("Failed to open file for scanning: %v", err)
			}
			defer tailer.file.Close()
			
			// Get cutoff time from database
			cutoffTime, err := getLatestTimestamp(db)
			if err != nil {
				log.Infof("No existing events in database, will process all entries")
				cutoffTime = time.Time{}
			} else {
				log.Infof("Found latest timestamp in database: %s", cutoffTime.Format("2006-01-02 15:04:05"))
			}
			
			// Scan the file
			if err := tailer.scanExistingFile(cutoffTime); err != nil {
				log.Fatalf("Failed to scan existing file: %v", err)
			}
			
			log.Info("Initial scan completed successfully")
		} else {
			log.Info("noTail=true but initialScan=false, nothing to do")
		}
		return
	}
	
	// Start tailing (this will run indefinitely)
	if err := tailer.tail(); err != nil {
		log.Fatalf("Failed to tail log file: %v", err)
	}
}
