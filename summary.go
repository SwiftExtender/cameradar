package cameradar

import (
	"encoding/json"
	"fmt"
	"io"
	//gortspclientauth "github.com/bluenviron/gortsplib/v5/pkg/headers"
)

// PrintStreams prints information on each stream.
func (s *Scanner) PrintStreams(streams []Stream) {
	if len(streams) == 0 {
		fmt.Println("No streams were found. Please make sure that your target is on an accessible network.")
	}

	success := 0
	for _, stream := range streams {
		if stream.Available {
			fmt.Printf("\tDevice RTSP URL:\t%s\n", (GetCameraRTSPURL(stream)))
			fmt.Println("\tAvailable:)")
			success++
		} else {
			fmt.Printf("\tAdmin panel URL:\t%s\n", GetCameraAdminPanelURL(stream))
			fmt.Println("\tAvailable:)")
		}

		if len(stream.Device) > 0 {
			fmt.Printf("\tDevice model:\t\t%s\n\n", stream.Device)
		}

		fmt.Printf("\tIP address:\t\t%s\n", stream.Address)
		fmt.Printf("\tRTSP port:\t\t%d\n", stream.Port)

		// switch stream.AuthenticationType {
		// case gortspclientauth.AuthBasic:
		// 	s.term.Infoln("\tAuth type:\t\tbasic")
		// case gortspclientauth.AuthDigest:
		// 	s.term.Infoln("\tAuth type:\t\tdigest")
		// default:
		// 	s.term.Infoln("\tThis camera does not require authentication")
		// }

		if stream.CredentialsFound {
			fmt.Printf("\tUsername:\t\t%s\n", stream.Username)
			fmt.Printf("\tPassword:\t\t%s\n", stream.Password)
		} else {
			fmt.Printf("\tUsername:\t\t%s\n", "not found")
			fmt.Printf("\tPassword:\t\t%s\n", "not found")
		}

		fmt.Printf("\tRTSP routes:")
		if stream.RouteFound {
			for _, route := range stream.Routes {
				fmt.Printf("\t\t\t\t/" + route)
			}
		} else {
			fmt.Println("not found")
		}

		fmt.Printf("\n\n")
	}

	if success > 1 {
		fmt.Printf("Successful attack: %d devices were accessed", len(streams))
	} else if success == 1 {
		fmt.Printf("Successful attack: one device was accessed")
	} else {
		fmt.Printf("Streams were found but none were accessed. They are most likely configured with secure credentials and routes. You can try adding entries to the dictionary or generating your own in order to attempt a bruteforce attack on the cameras.\n", ("\xE2\x9C\x96"))
	}
}

func (s *Scanner) Write(wc io.WriteCloser, streams []Stream) error {
	if wc == nil {
		return nil
	}
	defer wc.Close()

	jsonData, err := json.MarshalIndent(streams, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling results: %w", err)
	}

	_, err = wc.Write(jsonData)
	if err != nil {
		return fmt.Errorf("writing results to file: %w", err)
	}
	return nil

}
