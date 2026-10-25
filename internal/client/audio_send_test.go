package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealjay/mcp-whatsapp/internal/media"
)

// wavSine returns a one-second 8 kHz mono 16-bit PCM WAV file.
func wavSine() []byte {
	const rate, n = 8000, 8000
	var pcm bytes.Buffer
	for i := 0; i < n; i++ {
		binary.Write(&pcm, binary.LittleEndian, int16(8000*math.Sin(2*math.Pi*440*float64(i)/rate)))
	}
	var b bytes.Buffer
	b.WriteString("RIFF")
	binary.Write(&b, binary.LittleEndian, uint32(36+pcm.Len()))
	b.WriteString("WAVEfmt ")
	for _, v := range []any{uint32(16), uint16(1), uint16(1), uint32(rate), uint32(rate * 2), uint16(2), uint16(16)} {
		binary.Write(&b, binary.LittleEndian, v)
	}
	b.WriteString("data")
	binary.Write(&b, binary.LittleEndian, uint32(pcm.Len()))
	b.Write(pcm.Bytes())
	return b.Bytes()
}

// send_audio_message for a non-ogg file: the staged bytes are transcoded
// in memory and the voice note is sent without any temp path having to
// pass the outbound root (the old flow always refused it).
func TestSendConvertedVoiceNote(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed; media package stubs cover the conversion plumbing")
	}
	f := newSendFixture(t, true)
	staged := f.stage("mesaj vocal.wav", string(wavSine()))
	m, err := f.c.OpenOutboundMedia(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// What the send_audio_message handler does.
	converted, err := media.ConvertToOpusOgg(context.Background(), m.Data, m.Name)
	if err != nil {
		t.Fatal(err)
	}
	m.Data, m.Name = converted, strings.TrimSuffix(m.Name, filepath.Ext(m.Name))+".ogg"
	r := f.c.SendMediaWithOptions(context.Background(), SendMediaOptions{Recipient: "40700000001", Media: m})
	if !r.Success {
		t.Fatalf("send = %+v", r)
	}
	audio := f.tx.messages[0].GetAudioMessage()
	if audio == nil || !audio.GetPTT() || audio.GetSeconds() < 1 {
		t.Fatalf("not a voice note: %+v", f.tx.messages[0])
	}
	if !bytes.Equal(f.tx.uploads[0], converted) {
		t.Fatal("uploaded bytes are not the converted audio")
	}
}
