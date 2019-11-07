// Copyright 2019 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package jose

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAudiences_MarshalJSON(t *testing.T) {
	// Setup
	testCases := []struct {
		audiences []string
		expected  string
	}{
		{
			audiences: []string{"one"},
			expected:  `"one"`,
		},
		{
			audiences: []string{},
			expected:  `\[\]`,
		},
		{
			audiences: []string{"one", "two"},
			expected:  `^\[\s*"one",\s*"two"\s*\]?`,
		},
		{
			audiences: []string{},
			expected:  `^\[\]?`,
		},
	}

	// Act/Assert
	for _, test := range testCases {
		aud := Audiences{
			Aud: test.audiences,
		}
		result, err := json.Marshal(&aud)
		assert.NoError(t, err)
		assert.Regexp(t, regexp.MustCompile(test.expected), string(result))
	}
}

func TestAudiences_UnmarshalJSON(t *testing.T) {
	// Setup
	testCases := []struct {
		input    string
		expected []string
		err      error
	}{
		{
			input:    `"one"`,
			expected: []string{"one"},
			err:      nil,
		},
		{
			input:    `[]`,
			expected: nil,
			err:      nil,
		},
		{
			input:    `["one"]`,
			expected: []string{"one"},
			err:      nil,
		},
		{
			input:    `["one", "two"]`,
			expected: []string{"one", "two"},
			err:      nil,
		},
		{
			input:    `[1, "one"]`,
			expected: nil,
			err:      ErrJSONFormat,
		},
	}

	// Act/Assert
	for _, test := range testCases {
		var aud Audiences
		err := aud.UnmarshalJSON([]byte(test.input))
		assert.Equal(t, test.err, err)
		assert.Len(t, aud.Aud, len(test.expected))
		assert.Equal(t, test.expected, aud.Aud)
	}

}
