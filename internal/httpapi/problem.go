package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

type Problem struct {
	Type        string            `json:"type"`
	Title       string            `json:"title"`
	Status      int               `json:"status"`
	Detail      string            `json:"detail,omitempty"`
	Code        string            `json:"code"`
	RequestID   string            `json:"request_id"`
	RetryAfter  int               `json:"retry_after,omitempty"`
	FieldErrors map[string]string `json:"field_errors,omitempty"`
}

func (p Problem) Error() string {
	if p.Detail != "" {
		return p.Code + ": " + p.Detail
	}
	return p.Code
}

func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
	if status < 400 {
		status = http.StatusInternalServerError
	}
	requestID := RequestID(r.Context())
	p := Problem{
		Type:      "https://arca.local/problems/" + code,
		Title:     title,
		Status:    status,
		Detail:    detail,
		Code:      code,
		RequestID: requestID,
	}
	WriteProblemObject(w, p)
}

func WriteProblemObject(w http.ResponseWriter, problem Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(problem.Status)
	_ = json.NewEncoder(w).Encode(problem)
}

func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if status != http.StatusNoContent {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON body must contain one value")
	}
	return nil
}

func HandleError(logger *slog.Logger, w http.ResponseWriter, r *http.Request, err error) {
	var problem Problem
	if errors.As(err, &problem) {
		if problem.RequestID == "" {
			problem.RequestID = RequestID(r.Context())
		}
		if problem.Type == "" {
			problem.Type = "https://arca.local/problems/" + problem.Code
		}
		WriteProblemObject(w, problem)
		return
	}
	logger.Error("request failed", "request_id", RequestID(r.Context()), "method", r.Method, "path", r.URL.Path, "error", err)
	WriteProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
}
