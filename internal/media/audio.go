package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// AnalyzeOggOpus parses Ogg pages to extract duration (seconds) and generates
// a 64-byte waveform. Returns an error if the input is not a valid Ogg file.
func AnalyzeOggOpus(data []byte) (duration uint32, waveform []byte, err error) {
	if len(data) < 4 || string(data[0:4]) != "OggS" {
		return 0, nil, fmt.Errorf("not a valid Ogg file (missing OggS signature)")
	}

	var lastGranule uint64
	var sampleRate uint32 = 48000
	var preSkip uint16 = 0
	var foundOpusHead bool

	for i := 0; i < len(data); {
		if i+27 >= len(data) {
			break
		}

		if string(data[i:i+4]) != "OggS" {
			i++
			continue
		}

		granulePos := binary.LittleEndian.Uint64(data[i+6 : i+14])
		pageSeqNum := binary.LittleEndian.Uint32(data[i+18 : i+22])
		numSegments := int(data[i+26])

		if i+27+numSegments >= len(data) {
			break
		}
		segmentTable := data[i+27 : i+27+numSegments]

		pageSize := 27 + numSegments
		for _, segLen := range segmentTable {
			pageSize += int(segLen)
		}

		if !foundOpusHead && pageSeqNum <= 1 {
			pageData := data[i : i+pageSize]
			headPos := bytes.Index(pageData, []byte("OpusHead"))
			if headPos >= 0 && headPos+12 < len(pageData) {
				headPos += 8
				if headPos+12 <= len(pageData) {
					preSkip = binary.LittleEndian.Uint16(pageData[headPos+10 : headPos+12])
					sampleRate = binary.LittleEndian.Uint32(pageData[headPos+12 : headPos+16])
					foundOpusHead = true
				}
			}
		}

		if granulePos != 0 {
			lastGranule = granulePos
		}

		i += pageSize
	}

	if lastGranule > 0 {
		durationSeconds := float64(lastGranule-uint64(preSkip)) / float64(sampleRate)
		duration = uint32(math.Ceil(durationSeconds))
	} else {
		durationEstimate := float64(len(data)) / 2000.0
		duration = uint32(durationEstimate)
	}

	if duration < 1 {
		duration = 1
	} else if duration > 300 {
		duration = 300
	}

	waveform = PlaceholderWaveform(duration)
	return duration, waveform, nil
}

// PlaceholderWaveform generates a deterministic 64-byte synthetic waveform
// based on duration. Used when we can't derive a real waveform.
func PlaceholderWaveform(duration uint32) []byte {
	const waveformLength = 64
	waveform := make([]byte, waveformLength)

	r := rand.New(rand.NewPCG(uint64(duration), 0))

	baseAmplitude := 35.0
	d := int(duration)
	if d > 120 {
		d = 120
	}
	frequencyFactor := float64(d) / 30.0

	for i := range waveform {
		pos := float64(i) / float64(waveformLength)

		val := baseAmplitude * math.Sin(pos*math.Pi*frequencyFactor*8)
		val += (baseAmplitude / 2) * math.Sin(pos*math.Pi*frequencyFactor*16)

		val += (r.Float64() - 0.5) * 15

		fadeInOut := math.Sin(pos * math.Pi)
		val = val * (0.7 + 0.3*fadeInOut)

		val = val + 50

		if val < 0 {
			val = 0
		} else if val > 100 {
			val = 100
		}

		waveform[i] = byte(val)
	}

	return waveform
}

// ffmpegCommand is the converter binary; tests point it at a stub.
var ffmpegCommand = "ffmpeg"

// ConvertToOpusOgg transcodes audio bytes to opus/ogg with ffmpeg and
// returns the result. name only contributes its extension, which helps
// ffmpeg pick a demuxer.
//
// ffmpeg reads and writes inside a private directory (mode 0700) created
// for this call under the user's temp directory and removed when the call
// returns, on success and on failure alike. ffmpeg never sees a path the
// caller chose, so a file name cannot inject options and the bytes
// converted are exactly the ones the caller validated.
func ConvertToOpusOgg(ctx context.Context, data []byte, name string) ([]byte, error) {
	bin, lookErr := exec.LookPath(ffmpegCommand)
	if lookErr != nil {
		return nil, errors.New("ffmpeg not found on PATH; install ffmpeg to use voice messages")
	}

	dir, err := os.MkdirTemp("", "mcp-whatsapp-audio-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	input := filepath.Join(dir, "input"+audioExt(name))
	if err := os.WriteFile(input, data, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write temp input: %w", err)
	}
	output := filepath.Join(dir, "output.ogg")

	cmd := exec.CommandContext(ctx, bin,
		"-nostdin",
		"-i", input,
		"-c:a", "libopus",
		"-b:a", "32k",
		"-vbr", "on",
		"-compression_level", "10",
		"-y",
		output,
	)
	cmd.Env = minimalEnv()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg conversion failed: %w: %s", err, sanitizeStderr(stderr.String()))
	}
	out, err := os.ReadFile(output)
	if err != nil {
		return nil, fmt.Errorf("read ffmpeg output: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("ffmpeg produced no output")
	}
	return out, nil
}

// audioExt returns name's extension if it is short and alphanumeric, so
// the temp input keeps a hint for ffmpeg without carrying caller text.
func audioExt(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if len(ext) < 2 || len(ext) > 6 {
		return ""
	}
	for _, r := range ext[1:] {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return ""
		}
	}
	return ext
}

var safeEnvKeys = []string{"PATH", "TMPDIR", "TEMP", "TMP", "HOME"}

// minimalEnv returns a restricted environment for child processes, carrying
// only the variables ffmpeg needs (path resolution, temp dirs, home for codec
// config) while excluding credentials, tokens, and other sensitive values.
func minimalEnv() []string {
	env := make([]string, 0, len(safeEnvKeys))
	for _, k := range safeEnvKeys {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// absPathRe matches absolute file paths (Unix-style).
var absPathRe = regexp.MustCompile(`/[\w/.\-]+`)

// sanitizeStderr strips absolute file paths from ffmpeg stderr output and
// truncates to a maximum of 200 characters. This prevents leaking local
// filesystem layout to MCP callers.
func sanitizeStderr(s string) string {
	s = absPathRe.ReplaceAllString(s, "<path>")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
