package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const (
	awsCAuthSecret      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsCAuthSeed        = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
	awsCAuthFirstChunk  = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"
	awsCAuthSecondChunk = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"
	awsCAuthFinalChunk  = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"
	awsCAuthTrailer     = "df5735bd9f3295cd9386572292562fefc93ba94e80a0a1ddcbd652c4e0a75e6c"
)

func chunkedBody(sigs [4]string, trailer bool) string {
	var b strings.Builder
	b.WriteString("10000;chunk-signature=" + sigs[0] + "\r\n" + strings.Repeat("a", 65536) + "\r\n")
	b.WriteString("400;chunk-signature=" + sigs[1] + "\r\n" + strings.Repeat("a", 1024) + "\r\n")
	b.WriteString("0;chunk-signature=" + sigs[2] + "\r\n")
	if trailer {
		b.WriteString("first:1st\r\nsecond:2nd\r\nthird:3rd\r\nx-amz-trailer-signature:" + sigs[3] + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func TestChunksAreSignedAgainAsAWSSignsThem(t *testing.T) {
	placeholder := strings.Repeat("0", 64)
	for _, trailer := range []bool{false, true} {
		in := chunkedBody([4]string{placeholder, placeholder, placeholder, placeholder}, trailer)
		out, err := io.ReadAll(resignChunks(io.NopCloser(strings.NewReader(in)), chainFrom(awsCAuthSecret, "20130524T000000Z", "us-east-1", "s3", awsCAuthSeed), trailer))
		if err != nil {
			t.Fatal(err)
		}
		want := chunkedBody([4]string{awsCAuthFirstChunk, awsCAuthSecondChunk, awsCAuthFinalChunk, awsCAuthTrailer}, trailer)
		if !bytes.Equal(out, []byte(want)) {
			t.Errorf("trailer %v: the signatures differ from AWS's", trailer)
		}
		if len(out) != len(in) {
			t.Errorf("trailer %v: the body changed length from %d to %d", trailer, len(in), len(out))
		}
	}
}

func TestABrokenChunkedBodyFailsTheUpload(t *testing.T) {
	for _, in := range []string{
		"zz;chunk-signature=" + strings.Repeat("0", 64) + "\r\n",
		"5;no-signature\r\nhello\r\n",
		"5;chunk-signature=" + strings.Repeat("0", 64) + "\r\nhel",
	} {
		if _, err := io.ReadAll(resignChunks(io.NopCloser(strings.NewReader(in)), chainFrom(awsCAuthSecret, "20130524T000000Z", "us-east-1", "s3", awsCAuthSeed), false)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}
