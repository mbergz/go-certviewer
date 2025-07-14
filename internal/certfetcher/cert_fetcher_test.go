package certfetcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUrlValidInputs(t *testing.T) {
	inputs := []string{
		"example.com",
		"example.com:443",
		"www.example.com",
		"www.example.com:443",
		"https://example.com",
		"https://example.com:443",
		"https://www.example.com",
		"https://www.example.com:443",
	}

	for _, input := range inputs {
		res, err := parseUrlInput(input)
		assert.NoError(t, err)
		assert.NotNil(t, res)
	}
}

func TestParseUrlInvalidInputs(t *testing.T) {
	inputs := []struct {
		inputUrl       string
		expectedErrMsg string
	}{
		{"", "invalid input URL: empty host"},
		{"some test", `invalid input URL: parse "https://some test": invalid character " " in host name`},
		{"some\ntest", `invalid input URL: parse "https://some\ntest": net/url: invalid control character in URL`},
	}

	for _, input := range inputs {
		res, err := parseUrlInput(input.inputUrl)

		assert.Nil(t, res)
		assert.EqualError(t, err, input.expectedErrMsg,
			"Error should be: %v, got: %v", input.expectedErrMsg, err)
	}

}
