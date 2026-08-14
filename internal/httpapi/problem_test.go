package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsTrailingValues(t *testing.T) {
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"first":true} {"second":true}`))
	recorder := httptest.NewRecorder()
	var body map[string]any
	if err := DecodeJSON(recorder, request, &body); err == nil {
		t.Fatal("DecodeJSON accepted a second JSON value")
	}
}

