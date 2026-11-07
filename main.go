package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
)

type IPStat struct {
	IP    string
	Count int
}

func main() {
	logPath := flag.String("log", "/var/log/auth.log", "Path to Linux authentication log file")
	threshold := flag.Int("threshold", 5, "Minimum failed attempts to trigger an alert")
	flag.Parse()

	file, err := os.Open(*logPath)
	if err != nil {
		fmt.Printf("[!] Error opening log file (%s): %v\n", *logPath, err)
		os.Exit(1)
	}
	defer file.Close()

	failedRegex := regexp.MustCompile(`Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})`)

	ipCounts := make(map[string]int)
	totalFailed := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := failedRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			ip := matches[1]
			ipCounts[ip]++
			totalFailed++
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[!] Error reading log file: %v\n", err)
		os.Exit(1)
	}

	var stats []IPStat
	for ip, count := range ipCounts {
		if count >= *threshold {
			stats = append(stats, IPStat{IP: ip, Count: count})
		}
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	fmt.Println("=============================================================")
	fmt.Println(" 🛡️  GO-LOG-HUNTER | SSH Brute-Force Detection (T1110)")
	fmt.Println("=============================================================")
	fmt.Printf("[*] Scanning log file: %s\n", *logPath)
	fmt.Printf("[*] Alert Threshold:   %d failed attempts\n\n", *threshold)

	if len(stats) == 0 {
		fmt.Println("[+] No IPs exceeded the brute-force threshold.")
	} else {
		fmt.Println("[!] SUSPICIOUS IPs DETECTED:")
		fmt.Println("-------------------------------------------------------------")
		fmt.Printf("%-18s  %-18s  %s\n", "IP ADDRESS", "FAILED ATTEMPTS", "STATUS")
		fmt.Println("-------------------------------------------------------------")
		for _, stat := range stats {
			status := "[WARNING]"
			if stat.Count >= (*threshold * 4) {
				status = "[CRITICAL - BLOCK]"
			} else if stat.Count >= (*threshold * 2) {
				status = "[HIGH - INVESTIGATE]"
			}
			fmt.Printf("%-18s  %-18d  %s\n", stat.IP, stat.Count, status)
		}
		fmt.Println("-------------------------------------------------------------")
	}
	fmt.Printf("[+] Analysis complete. Total failed events parsed: %d\n", totalFailed)
}
