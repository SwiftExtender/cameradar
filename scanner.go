package cameradar

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

const (
	defaultCredentialDictionaryPath = "${GOPATH}/src/github.com/Ullaakut/cameradar/dictionaries/credentials.json"
	defaultRouteDictionaryPath      = "${GOPATH}/src/github.com/Ullaakut/cameradar/dictionaries/routes"
)

// Scanner represents a cameradar scanner. It scans a network and
// attacks all streams found to get their RTSP credentials.
type Scanner struct {
	targets                  []string
	ports                    []string
	debug                    bool
	verbose                  bool
	scanSpeed                int
	attackInterval           time.Duration
	timeout                  time.Duration
	credentialDictionaryPath string
	routeDictionaryPath      string

	credentials Credentials
	routes      Routes
}

type PortStatus struct {
	host     string
	port     int
	isOpened bool
	isRTSP   bool
	banner   string
}

func isPortRTSP(conn net.Conn) (bool, []byte, error) {
	req := "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n"
	buffer := make([]byte, 4)
	fullbuffer := make([]byte, 256)
	defer conn.Close()
	_, err := conn.Write([]byte(req))
	if err != nil {
		return false, nil, err
	}
	_, err = conn.Read(fullbuffer)
	if err != nil {
		return false, nil, err
	}
	if len(fullbuffer) >= 4 {
		copy(buffer, fullbuffer[:4])
	}
	if string(buffer) == "RTSP" {
		return true, fullbuffer, nil
	}
	return false, fullbuffer, nil
}

func isPortOpened(protocol, hostname string, port int, timeout time.Duration, wg *sync.WaitGroup, results chan<- PortStatus) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.DialTimeout(protocol, address, timeout*time.Second)
	if err != nil {
		results <- PortStatus{host: hostname, port: port, isOpened: false, isRTSP: false, banner: ""}
		return
	}
	status, banner, err := isPortRTSP(conn)
	if err != nil {
		results <- PortStatus{host: hostname, port: port, isOpened: true, isRTSP: false, banner: string(banner)}
		return
	}
	if status {
		results <- PortStatus{host: hostname, port: port, isOpened: true, isRTSP: true, banner: string(banner)}
		return
	}
	results <- PortStatus{host: hostname, port: port, isOpened: true, isRTSP: false, banner: string(banner)}
}

// ScanHost performs a port scan on a host for the given ports
func (s *Scanner) ScanHosts() ([]Stream, error) {
	var wg sync.WaitGroup
	results := make(chan PortStatus, len(s.ports))

	for _, host := range s.targets {
		// Launch goroutine for each port
		for _, port := range s.ports {
			var numport int
			// Parse integer from string
			_, err := fmt.Sscanf(port, "%d", &numport)
			if err != nil {
				fmt.Errorf("Wrong port value:", err)
				continue
			}
			wg.Add(1)
			go isPortOpened("tcp", host, numport, s.timeout, &wg, results)
		}
	}
	wg.Wait()
	close(results)

	// Collect results

	var streams []Stream
	for result := range results {
		if result.isRTSP {
			streams = append(streams, Stream{
				//Device:  port.Service.Product,
				Address:        result.host,
				Port:           uint16(result.port),
				BannerResponse: result.banner,
			})
		}
	}

	return streams, nil
}

// New creates a new Cameradar Scanner and applies the given options.
func New(options ...func(*Scanner)) (*Scanner, error) {
	scanner := &Scanner{
		//client:                   gortsplib.Client{},
		credentialDictionaryPath: defaultCredentialDictionaryPath,
		routeDictionaryPath:      defaultRouteDictionaryPath,
	}

	for _, option := range options {
		option(scanner)
	}

	gopath := os.Getenv("GOPATH")
	if gopath == "" && scanner.credentialDictionaryPath == defaultCredentialDictionaryPath && scanner.routeDictionaryPath == defaultRouteDictionaryPath {
		fmt.Println("No $GOPATH was found.\nDictionaries may not be loaded properly, please set your $GOPATH to use the default dictionaries.")
	}

	scanner.credentialDictionaryPath = os.ExpandEnv(scanner.credentialDictionaryPath)
	scanner.routeDictionaryPath = os.ExpandEnv(scanner.routeDictionaryPath)

	err := scanner.LoadTargets()
	if err != nil {
		return nil, fmt.Errorf("unable to parse target file: %v", err)
	}

	fmt.Println("Loading credentials")
	err = scanner.LoadCredentials()
	if err != nil {
		return nil, fmt.Errorf("unable to load credentials dictionary: %v", err)
	}

	fmt.Println("Loading routes")
	err = scanner.LoadRoutes()
	if err != nil {
		return nil, fmt.Errorf("unable to load credentials dictionary: %v", err)
	}
	fmt.Println("Beginning scan")
	return scanner, nil
}

// WithTargets specifies the targets to scan and attack.
func WithTargets(targets []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.targets = targets
	}
}

// WithPorts specifies the ports to scan and attack.
func WithPorts(ports []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.ports = ports
	}
}

// WithDebug specifies whether or not to enable debug logs.
func WithDebug(debug bool) func(s *Scanner) {
	return func(s *Scanner) {
		s.debug = debug
	}
}

// WithVerbose specifies whether or not to enable verbose logs.
func WithVerbose(verbose bool) func(s *Scanner) {
	return func(s *Scanner) {
		s.verbose = verbose
	}
}

// WithCustomCredentials specifies a custom credential dictionary
// to use for the attacks.
func WithCustomCredentials(dictionaryPath string) func(s *Scanner) {
	return func(s *Scanner) {
		s.credentialDictionaryPath = dictionaryPath
	}
}

// WithCustomRoutes specifies a custom route dictionary
// to use for the attacks.
func WithCustomRoutes(dictionaryPath string) func(s *Scanner) {
	return func(s *Scanner) {
		s.routeDictionaryPath = dictionaryPath
	}
}

// WithScanSpeed specifies the speed at which the scan should be executed. Faster
// means easier to detect, slower has bigger timeout values and is more silent.
func WithScanSpeed(speed int) func(s *Scanner) {
	return func(s *Scanner) {
		s.scanSpeed = speed
	}
}

// WithAttackInterval specifies the interval of time during which Cameradar
// should wait between each attack attempt during bruteforcing.
// Setting a high value for this obviously makes attacks much slower.
func WithAttackInterval(interval time.Duration) func(s *Scanner) {
	return func(s *Scanner) {
		s.attackInterval = interval
	}
}

// WithTimeout specifies the amount of time after which attack requests should
// timeout. This should be high if the network you are attacking has a poor
// connectivity or that you are located far away from it.
func WithTimeout(timeout time.Duration) func(s *Scanner) {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

// func WithClient(targets []string) func(s *Scanner) {
// 	return func(s *Scanner) {
// 		s.targets = targets
// 	}
// }
