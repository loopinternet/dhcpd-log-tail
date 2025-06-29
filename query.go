package main

import (
	"database/sql"
	"flag"
	"fmt"
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
	dbFile          = flag.String("db", "dhcp.db", "SQLite database file path")
	logLevel        = flag.String("logLevel", "info", "log level can be trace, debug, info, warn, or error")
	logTimestamp    = flag.Bool("logTimestamp", true, "show timestamp in logs")
	
	// Query flags
	queryMAC        = flag.String("mac", "", "query last seen event for MAC address")
	queryIP         = flag.String("ip", "", "query last lease for IP address")
	queryDenied     = flag.Bool("denied", false, "query denied leases")
	deniedLimit     = flag.Int("limit", 10, "limit for denied leases query")
	showCount       = flag.Bool("count", false, "show database statistics and counts")
	jsonOutput      = flag.Bool("json", false, "output results in JSON format")
	showHelp        = flag.Bool("help", false, "show help message")
)

// Query functions

// GetLastSeenMAC returns the last seen event for a MAC address
func getLastSeenMAC(db *sql.DB, macAddress string) (*DHCPEvent, error) {
	query := `
	SELECT id, timestamp, mac_address, ip_address, message_type, relay_ip,
		   network_name, hostname, reason, requested_ip, server_ip,
		   lease_age, raw_message, created_at
	FROM dhcp_events
	WHERE mac_address = ?
	ORDER BY timestamp DESC
	LIMIT 1`

	row := db.QueryRow(query, macAddress)
	return scanDHCPEvent(row)
}

// GetLastLeaseForIP returns the last lease issued for an IP address
func getLastLeaseForIP(db *sql.DB, ipAddress string) (*DHCPEvent, error) {
	query := `
	SELECT id, timestamp, mac_address, ip_address, message_type, relay_ip,
		   network_name, hostname, reason, requested_ip, server_ip,
		   lease_age, raw_message, created_at
	FROM dhcp_events
	WHERE ip_address = ? AND message_type = 'ACK'
	ORDER BY timestamp DESC
	LIMIT 1`

	row := db.QueryRow(query, ipAddress)
	return scanDHCPEvent(row)
}

// GetDeniedLeases returns MAC addresses being denied leases
func getDeniedLeases(db *sql.DB, limit int) ([]*DHCPEvent, error) {
	query := `
	SELECT id, timestamp, mac_address, ip_address, message_type, relay_ip,
		   network_name, hostname, reason, requested_ip, server_ip,
		   lease_age, raw_message, created_at
	FROM dhcp_events
	WHERE message_type = 'NAK' OR reason LIKE '%no free leases%' OR reason LIKE '%unknown client%'
	ORDER BY timestamp DESC
	LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*DHCPEvent
	for rows.Next() {
		event, err := scanDHCPEventFromRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

// GetDatabaseCounts returns statistics about the database
func getDatabaseCounts(db *sql.DB) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Total events
	var totalEvents int64
	err := db.QueryRow("SELECT COUNT(*) FROM dhcp_events").Scan(&totalEvents)
	if err != nil {
		return nil, err
	}
	stats["total_events"] = totalEvents
	
	// Events by message type
	rows, err := db.Query(`
		SELECT message_type, COUNT(*) 
		FROM dhcp_events 
		WHERE message_type != '' 
		GROUP BY message_type 
		ORDER BY COUNT(*) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	messageTypes := make(map[string]int64)
	for rows.Next() {
		var msgType string
		var count int64
		if err := rows.Scan(&msgType, &count); err != nil {
			return nil, err
		}
		messageTypes[msgType] = count
	}
	stats["message_types"] = messageTypes
	
	// Unique MAC addresses
	var uniqueMACs int64
	err = db.QueryRow("SELECT COUNT(DISTINCT mac_address) FROM dhcp_events WHERE mac_address != ''").Scan(&uniqueMACs)
	if err != nil {
		return nil, err
	}
	stats["unique_macs"] = uniqueMACs
	
	// Unique IP addresses
	var uniqueIPs int64
	err = db.QueryRow("SELECT COUNT(DISTINCT ip_address) FROM dhcp_events WHERE ip_address != ''").Scan(&uniqueIPs)
	if err != nil {
		return nil, err
	}
	stats["unique_ips"] = uniqueIPs
	
	// Date range
	var earliestDate, latestDate time.Time
	err = db.QueryRow("SELECT MIN(timestamp), MAX(timestamp) FROM dhcp_events").Scan(&earliestDate, &latestDate)
	if err == nil {
		stats["earliest_event"] = earliestDate
		stats["latest_event"] = latestDate
	}
	
	// Denied events count
	var deniedCount int64
	err = db.QueryRow(`
		SELECT COUNT(*) FROM dhcp_events 
		WHERE message_type = 'NAK' OR reason LIKE '%no free leases%' OR reason LIKE '%unknown client%'
	`).Scan(&deniedCount)
	if err != nil {
		return nil, err
	}
	stats["denied_events"] = deniedCount
	
	return stats, nil
}

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

func printUsage() {
	fmt.Println("DHCP Log Query Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  Query last seen event for a MAC address:")
	fmt.Println("    dhcp-query -mac 3c:94:d5:4f:a0:c1")
	fmt.Println()
	fmt.Println("  Query last lease for an IP address:")
	fmt.Println("    dhcp-query -ip 192.168.1.100")
	fmt.Println()
	fmt.Println("  Query denied leases:")
	fmt.Println("    dhcp-query -denied -limit 20")
	fmt.Println()
	fmt.Println("  Show database statistics:")
	fmt.Println("    dhcp-query -count")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
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

	// Show help if requested or no queries specified
	if *showHelp || (*queryMAC == "" && *queryIP == "" && !*queryDenied && !*showCount) {
		printUsage()
		return
	}

	// Open database
	db, err := sql.Open("sqlite3", *dbFile)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Handle query operations
	if *queryMAC != "" {
		event, err := getLastSeenMAC(db, *queryMAC)
		if err != nil {
			if err == sql.ErrNoRows {
				fmt.Printf("No events found for MAC address: %s\n", *queryMAC)
			} else {
				log.Fatalf("Failed to query MAC address: %v", err)
			}
			return
		}

		fmt.Printf("Last seen event for MAC %s:\n", *queryMAC)
		fmt.Printf("  Timestamp: %s\n", event.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Action: %s\n", event.MessageType)
		if event.IPAddress != "" {
			fmt.Printf("  IP: %s\n", event.IPAddress)
		}
		if event.RequestedIP != "" {
			fmt.Printf("  Requested IP: %s\n", event.RequestedIP)
		}
		if event.RelayIP != "" {
			fmt.Printf("  Relay: %s\n", event.RelayIP)
		}
		if event.NetworkName != "" {
			fmt.Printf("  Network: %s\n", event.NetworkName)
		}
		if event.Hostname != "" {
			fmt.Printf("  Hostname: %s\n", event.Hostname)
		}
		if event.Reason != "" {
			fmt.Printf("  Reason: %s\n", event.Reason)
		}
		return
	}

	if *queryIP != "" {
		event, err := getLastLeaseForIP(db, *queryIP)
		if err != nil {
			if err == sql.ErrNoRows {
				fmt.Printf("No lease found for IP address: %s\n", *queryIP)
			} else {
				log.Fatalf("Failed to query IP address: %v", err)
			}
			return
		}

		fmt.Printf("Last lease for IP %s:\n", *queryIP)
		fmt.Printf("  Timestamp: %s\n", event.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("  MAC: %s\n", event.MACAddress)
		if event.Hostname != "" {
			fmt.Printf("  Hostname: %s\n", event.Hostname)
		}
		if event.RelayIP != "" {
			fmt.Printf("  Relay: %s\n", event.RelayIP)
		}
		return
	}

	if *queryDenied {
		events, err := getDeniedLeases(db, *deniedLimit)
		if err != nil {
			log.Fatalf("Failed to query denied leases: %v", err)
		}

		if len(events) == 0 {
			fmt.Println("No denied lease events found")
			return
		}

		fmt.Printf("Found %d denied lease events:\n", len(events))
		fmt.Println()
		for i, event := range events {
			fmt.Printf("[%d] %s\n", i+1, event.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Printf("    MAC: %s\n", event.MACAddress)
			fmt.Printf("    Action: %s\n", event.MessageType)
			if event.RelayIP != "" {
				fmt.Printf("    Relay: %s\n", event.RelayIP)
			}
			if event.NetworkName != "" {
				fmt.Printf("    Network: %s\n", event.NetworkName)
			}
			if event.IPAddress != "" {
				fmt.Printf("    IP: %s\n", event.IPAddress)
			}
			if event.RequestedIP != "" {
				fmt.Printf("    Requested IP: %s\n", event.RequestedIP)
			}
			if event.Reason != "" {
				fmt.Printf("    Reason: %s\n", event.Reason)
			}
			fmt.Println()
		}
	}

	if *showCount {
		stats, err := getDatabaseCounts(db)
		if err != nil {
			log.Fatalf("Failed to get database statistics: %v", err)
		}

		fmt.Println("Database Statistics:")
		fmt.Printf("  Total Events: %d\n", stats["total_events"])
		fmt.Printf("  Unique MAC Addresses: %d\n", stats["unique_macs"])
		fmt.Printf("  Unique IP Addresses: %d\n", stats["unique_ips"])
		fmt.Printf("  Denied Events: %d\n", stats["denied_events"])
		
		if earliest, ok := stats["earliest_event"].(time.Time); ok {
			fmt.Printf("  Earliest Event: %s\n", earliest.Format("2006-01-02 15:04:05"))
		}
		if latest, ok := stats["latest_event"].(time.Time); ok {
			fmt.Printf("  Latest Event: %s\n", latest.Format("2006-01-02 15:04:05"))
		}
		
		fmt.Println("\nEvents by Message Type:")
		if messageTypes, ok := stats["message_types"].(map[string]int64); ok {
			for msgType, count := range messageTypes {
				fmt.Printf("  %s: %d\n", msgType, count)
			}
		}
		return
	}
} 