package cameradar

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bluenviron/gortsplib/v5"

	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/bluenviron/gortsplib/v5/pkg/headers"
	"github.com/pion/rtp"
)

// Authentication types.
// const (
// 	authNone   = 0
// 	authBasic  = 1
// 	authDigest = 2
// )

type AuthInfo struct {
	Type      string
	Realm     string
	Nonce     string
	Opaque    string
	Stale     string
	Algorithm string
	Qop       string
	Header    string
}

// Route that should never be a constructor default.
const dummyRoute = "/0x8b6c42"

// Attack attacks the given targets and returns the accessed streams.
func (s *Scanner) Attack(targets []Stream) ([]Stream, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no stream found")
	}

	// Most cameras will be accessed successfully with these two attacks.
	s.term.StartStepf("Attacking routes of %d streams", len(targets))
	streams := s.AttackRoute(targets)

	s.term.StartStepf("Attempting to detect authentication methods of %d streams", len(targets))
	streams = s.DetectAuthMethods(streams)

	s.term.StartStepf("Attacking credentials of %d streams", len(targets))
	streams = s.AttackCredentials(streams)

	s.term.StartStep("Validating that streams are accessible")
	streams = s.ValidateStreams(streams)

	// But some cameras run GST RTSP Server which prioritizes 401 over 404 contrary to most cameras.
	// For these cameras, running another route attack will solve the problem.
	for _, stream := range streams {
		if !stream.RouteFound || !stream.CredentialsFound || !stream.Available {
			s.term.StartStepf("Second round of attacks")
			streams = s.AttackRoute(streams)

			s.term.StartStep("Validating that streams are accessible")
			streams = s.ValidateStreams(streams)

			break
		}
	}

	s.term.EndStep()

	return streams, nil
}

// ValidateStreams tries to setup the stream to validate whether or not it is available.
func (s *Scanner) ValidateStreams(targets []Stream) []Stream {
	for i := range targets {
		targets[i].Available = s.validateStream(targets[i])
		time.Sleep(s.attackInterval)
	}

	return targets
}

// AttackCredentials attempts to guess the provided targets' credentials using the given
// dictionary or the default dictionary if none was provided by the user.
func (s *Scanner) AttackCredentials(targets []Stream) []Stream {
	resChan := make(chan Stream)
	defer close(resChan)

	for i := range targets {
		go s.attackCameraCredentials(targets[i], resChan)
	}

	for range targets {
		attackResult := <-resChan
		if attackResult.CredentialsFound {
			targets = replace(targets, attackResult)
		}
	}

	return targets
}

// AttackRoute attempts to guess the provided targets' streaming routes using the given
// dictionary or the default dictionary if none was provided by the user.
func (s *Scanner) AttackRoute(targets []Stream) []Stream {
	resChan := make(chan Stream)
	defer close(resChan)

	for i := range targets {
		go s.attackCameraRoute(targets[i], resChan)
	}

	for range targets {
		attackResult := <-resChan
		if attackResult.RouteFound {
			targets = replace(targets, attackResult)
		}
	}

	return targets
}

// DetectAuthMethods attempts to guess the provided targets' authentication types, between
// digest, basic auth or none at all.
func (s *Scanner) DetectAuthMethods(targets []Stream) []Stream {
	for i := range targets {
		targets[i].AuthenticationType = s.detectAuthMethod(targets[i])
		time.Sleep(s.attackInterval)

		var authMethod string
		switch targets[i].AuthenticationType {
		case 0:
			authMethod = "no"
		case 1:
			authMethod = "basic"
		case 2:
			authMethod = "digest"
		default:
			authMethod = "unknown:" + string(targets[i].AuthenticationType)
		}

		s.term.Debugf("Stream %s uses %s authentication method\n", GetCameraRTSPURL(targets[i]), authMethod)
	}

	return targets
}

func (s *Scanner) attackCameraCredentials(target Stream, resChan chan<- Stream) {
	for _, username := range s.credentials.Usernames {
		for _, password := range s.credentials.Passwords {
			ok, media := s.credAttack(target, username, password)
			if ok {
				target.CredentialsFound = true
				target.Username = username
				target.Password = password
				target.Media = media
				resChan <- target
				return
			}
			time.Sleep(s.attackInterval)
		}
	}

	target.CredentialsFound = false
	resChan <- target
}

func (s *Scanner) attackCameraRoute(target Stream, resChan chan<- Stream) {
	// If the stream responds positively to the dummy route, it means
	// it doesn't require (or respect the RFC) a route and the attack
	// can be skipped.
	ok := s.routeAttack(target, dummyRoute)
	if ok {
		target.RouteFound = true
		target.Routes = append(target.Routes, "/")
		resChan <- target
		return
	}

	// Otherwise, bruteforce the routes.
	for _, route := range s.routes {
		ok := s.routeAttack(target, route)
		if ok {
			target.RouteFound = true
			target.Routes = append(target.Routes, route)
		}
		time.Sleep(s.attackInterval)
	}

	resChan <- target
}

func parseAuthHeader(wwwAuthenticate string) *AuthInfo {
	info := &AuthInfo{Header: wwwAuthenticate}

	if strings.HasPrefix(strings.ToLower(wwwAuthenticate), "digest") {
		info.Type = "Digest"
		// Extract digest parameters
		parts := strings.SplitN(wwwAuthenticate, " ", 2)
		if len(parts) > 1 {
			params := parts[1]
			// Simple parsing of key=value pairs
			pairs := strings.Split(params, ",")
			for _, pair := range pairs {
				kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
				if len(kv) == 2 {
					key := strings.TrimSpace(kv[0])
					value := strings.Trim(strings.TrimSpace(kv[1]), `"`)

					switch key {
					case "realm":
						info.Realm = value
					case "nonce":
						info.Nonce = value
					case "opaque":
						info.Opaque = value
					case "stale":
						info.Stale = value
					case "algorithm":
						info.Algorithm = value
					case "qop":
						info.Qop = value
					}
				}
			}
		}
	} else if strings.HasPrefix(strings.ToLower(wwwAuthenticate), "basic") {
		info.Type = "Basic"
		parts := strings.SplitN(wwwAuthenticate, " ", 2)
		if len(parts) > 1 {
			info.Realm = strings.Trim(parts[1], `"`)
		}
	}

	return info
}

func detectAuthentication(resp *base.Response) *AuthInfo {
	if authHeaders, ok := resp.Header["WWW-Authenticate"]; ok && len(authHeaders) > 0 {
		return parseAuthHeader(authHeaders[0])
	}
	return nil
}

// func detectTrack(sessionData description.Session) string {
//  	format := sessionData.FindFormat()
//   {
//         fmt.Printf("Media #%d: ", i+1)

//         switch fmt := media.Format.(type) {
//         case *format.H264:
//             fmt.Printf("H264 Video - SPS: %d bytes, PPS: %d bytes\n",
//                 len(fmt.SPS), len(fmt.PPS))

//         case *format.H265:
//             fmt.Printf("H265 Video - VPS: %d bytes, SPS: %d bytes, PPS: %d bytes\n",
//                 len(fmt.VPS), len(fmt.SPS), len(fmt.PPS))

//         case *format.AAC:
//             fmt.Printf("AAC Audio - Config: %v\n", fmt.Config)

//         case *format.Opus:
//             fmt.Printf("Opus Audio - %d channels\n", fmt.ChannelCount)

//         case *format.VP8:
//             fmt.Println("VP8 Video")

//         case *format.VP9:
//             fmt.Println("VP9 Video")

//         case *format.MJPEG:
//             fmt.Println("MJPEG Video")

//         default:
//             fmt.Printf("Unsupported format: %T\n", media.Format)
//         }
//  }
// }
// func detectTrack(sessionData description.Session) string {
// 	mes := ""
// 	medias := sessionData.Medias
// 	for i, media := range medias {
// 		switch t := media[i].Formats.(type) {
// 		case *gortsplib.H264:
// 			mes = fmt.Sprintf("Track %d: H264 (SPS: %v, PPS: %v)", i, t.SPS, t.PPS)
// 		case *gortsplib.TrackGeneric:
// 			mes = fmt.Sprintf("Track %d: Generic (Media: %v)", i, t.Media)
// 		case *gortsplib.TrackG711:
// 			mes = fmt.Sprintf("Track %d: G711 (MuLAW: %t)", i, t.MULaw)
// 		case *gortsplib.TrackG722:
// 			mes = fmt.Sprintf("Track %d: G722", i)
// 		//case *gortsplib.TrackGenericPayload:
// 		//	mes = fmt.Sprintf("Track %d: GenericPayload (FMTP: %s, RTPMap: %s, Type: %d)", i, t.FMTP, t.RTPMap, t.Type)
// 		case *gortsplib.TrackH265:
// 			mes = fmt.Sprintf("Track %d: H265 (MaxDONDiff: %d, PPS: %v, PayloadType: %d, SPS: %v, VPS: %v)", i, t.MaxDONDiff, t.PPS, t.PayloadType, t.SPS, t.VPS)
// 		case *gortsplib.TrackJPEG:
// 			mes = fmt.Sprintf("Track %d: JPEG (ConnectionInformation.AddressType: %s)", i, t.MediaDescription().ConnectionInformation.AddressType) //make more then
// 		case *gortsplib.TrackLPCM:
// 			mes = fmt.Sprintf("Track %d: LPCM (BitDepth: %d, ChannelCount: %d, PayloadType: %d, SampleRate: %d)", i, t.BitDepth, t.ChannelCount, t.PayloadType, t.SampleRate)
// 		case *gortsplib.TrackMPEG2Audio:
// 			mes = fmt.Sprintf("Track %d: MPEG2Audio (Control: %s, Codec: %s)", i, t.GetControl(), t.String()) //make more then
// 		case *gortsplib.TrackMPEG2Video:
// 			mes = fmt.Sprintf("Track %d: MPEG2Video (Control: %s, Codec: %s)", i, t.GetControl(), t.String()) //make more then
// 		case *gortsplib.TrackMPEG4Audio:
// 			mes = fmt.Sprintf("Track %d: MPEG4Audio (Control: %s, Codec: %s)", i, t.GetControl(), t.String()) //make more then
// 		case *gortsplib.TrackOpus:
// 			mes = fmt.Sprintf("Track %d: Opus (Control: %s, Codec: %s)", i, t.GetControl(), t.String()) //make more then
// 		case *gortsplib.TrackVP8:
// 			mes = fmt.Sprintf("Track %d: Vp8 (Control: %s, Codec: %s)", i, t.GetControl(), t.String()) //make more then
// 		case *gortsplib.TrackVP9:
// 			mes = fmt.Sprintf("Track %d: Vp9 (Control: %s, Codec: %s)", i, t.GetControl(), t.String()) //make more then
// 		case *gortsplib.TrackVorbis:
// 			mes = fmt.Sprintf("Track %d: Vorbis (Control: %s, Codec: %s)", i, t.GetControl(), t.String()) //make more then
// 		default:
// 			mes = "Unknown type"
// 		}
// 	}
// 	return mes
// }

func (s *Scanner) detectAuthMethod(stream Stream) headers.AuthMethod {
	rawURL := fmt.Sprintf(("rtsp://%s:%d/%s"), stream.Address, stream.Port, stream.Route())
	attackURL, err := base.ParseURL(rawURL)
	if err != nil {
		s.term.Errorf("Url parsing %q failed: %v", rawURL, err)
		return -1
	}

	client := gortsplib.Client{
		Scheme: attackURL.Scheme,
		Host:   attackURL.Host,
	}

	err = client.Start()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
		return -1
	}

	_, rc, err := client.Describe(attackURL)
	if err != nil {
		s.term.Errorf("Getinfo failed: %v", err)
		return -1
	}
	if s.debug {
		s.term.Debugln("DESCRIBE", attackURL, "RTSP/1.0 >", rc, "Response URL")
	}

	authinfo := detectAuthentication(rc)
	if authinfo.Type == "digest" {
		return 2
	} else if authinfo.Type == "basic" {
		return 1
	}
	return 0
}

func (s *Scanner) routeAttack(stream Stream, route string) bool {
	rawURL := fmt.Sprintf(("rtsp://%s:%d/%s"), stream.Address, stream.Port, stream.Route())
	attackURL, err := base.ParseURL(rawURL)
	if err != nil {
		s.term.Errorf("Url parsing %q failed: %v", rawURL, err)
		return false
	}

	client := gortsplib.Client{
		Scheme: attackURL.Scheme,
		Host:   attackURL.Host,
	}

	err = client.Start()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
		return false
	}

	_, rc, err := client.Describe(attackURL)
	if err != nil {
		s.term.Errorf("Getinfo failed: %v", err)
		return false
	}
	if s.debug {
		s.term.Debugln("DESCRIBE", attackURL, "RTSP/1.0 >", rc, "Response URL")
	}
	// If it's a 401 or 403, it means that the credentials are wrong but the route might be okay.
	// If it's a 200, the stream is accessed successfully.
	if rc.StatusCode == base.StatusOK || rc.StatusCode == base.StatusUnauthorized || rc.StatusCode == base.StatusForbidden {
		return true
	}
	return false
}

func (s *Scanner) credAttack(stream Stream, username string, password string) (bool, description.Session) {
	rawURL := fmt.Sprintf(("rtsp://%s:%d/%s"), stream.Address, stream.Port, stream.Route())
	attackURL, err := base.ParseURL(rawURL)
	if err != nil {
		s.term.Errorf("Url parsing %q failed: %v", rawURL, err)
		return false, description.Session{}
	}

	client := gortsplib.Client{
		Scheme: attackURL.Scheme,
		Host:   attackURL.Host,
	}

	err = client.Start()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
		return false, description.Session{}
	}

	desc, rc, err := client.Describe(attackURL)
	if err != nil {
		s.term.Errorf("Getinfo failed: %v", err)
		return false, description.Session{}
	}
	if s.debug {
		s.term.Debugln("DESCRIBE", attackURL, "RTSP/1.0 >", rc, "Response URL")
	}

	// If it's a 404, it means that the route is incorrect but the credentials might be okay.
	// If it's a 200, the stream is accessed successfully.
	if rc.StatusCode == base.StatusOK || rc.StatusCode == base.StatusNotFound {
		return true, *desc
	}
	return false, description.Session{}
}

func (s *Scanner) validateStream(stream Stream) bool {
	rawURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		stream.Username,
		stream.Password,
		stream.Address,
		stream.Port,
		stream.Route(),
	)
	attackURL, err := base.ParseURL(rawURL)
	if err != nil {
		s.term.Errorf("Url parsing %q failed: %v", rawURL, err)
		return false
	}

	client := gortsplib.Client{
		Scheme: attackURL.Scheme,
		Host:   attackURL.Host,
	}

	err = client.Start()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
		return false
	}
	defer client.Close()

	if s.debug {
		s.term.Debugln("SETUP", attackURL, "RTSP/1.0 >")
	}

	err = client.SetupAll(stream.Media.BaseURL, stream.Media.Medias)
	if err != nil {
		return false
	} else {
		client.OnPacketRTPAny(func(media *description.Media, _ format.Format, pkt *rtp.Packet) {
			err2 := client.WritePacketRTP(media, pkt)
			if err2 != nil {
				log.Printf("ERR: %v", err2)
			}
		})

		_, err = client.Play(nil)
		if err != nil {
			s.term.Errorf("Error of recording: %s in URL: %s", err, attackURL.String())
			return false
		}
		err = client.StartRecording(rawURL, &stream.Media)
		if err != nil {
			s.term.Errorf("Error of recording: %s in URL: %s", err, attackURL.String())
			return false
		}
		// wait until a fatal error
		//panic(reader.Wait())
		return false
	}
}

// Set custom timeout.
//_ = c.Setopt(curl.OPT_TIMEOUT_MS, int(s.timeout/time.Millisecond))

// Enable verbose logs if verbose mode is on.
// if s.verbose {
// 	_ = c.Setopt(curl.OPT_VERBOSE, 1)
// } else {
// 	_ = c.Setopt(curl.OPT_VERBOSE, 0)
// }
//}
