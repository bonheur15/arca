package preview

import (
	"errors"
	"mime"
	"path/filepath"
	"strings"
)

type Kind string

const (
	KindImage    Kind = "image"
	KindPDF      Kind = "pdf"
	KindText     Kind = "text"
	KindMarkdown Kind = "markdown"
	KindAudio    Kind = "audio"
	KindVideo    Kind = "video"
	KindDownload Kind = "download"
)

type Decision struct {
	Kind               Kind
	Inline             bool
	ContentType        string
	Sandbox            bool
	MaximumPreviewSize int64
}

func Decide(name, reportedType string) Decision {
	extension := strings.ToLower(filepath.Ext(name))
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(reportedType, ";")[0]))
	if contentType == "" || contentType == "application/octet-stream" {
		contentType = mime.TypeByExtension(extension)
		contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	if extension == ".html" || extension == ".htm" || extension == ".svg" || contentType == "text/html" || contentType == "image/svg+xml" {
		return Decision{Kind: KindDownload, ContentType: safeType(contentType)}
	}
	if contentType == "application/pdf" || extension == ".pdf" {
		return Decision{Kind: KindPDF, Inline: true, Sandbox: true, ContentType: "application/pdf"}
	}
	if strings.HasPrefix(contentType, "image/") {
		return Decision{Kind: KindImage, Inline: true, ContentType: contentType, MaximumPreviewSize: 50 << 20}
	}
	if strings.HasPrefix(contentType, "audio/") {
		return Decision{Kind: KindAudio, Inline: true, ContentType: contentType}
	}
	if strings.HasPrefix(contentType, "video/") {
		return Decision{Kind: KindVideo, Inline: true, ContentType: contentType}
	}
	if extension == ".md" || extension == ".markdown" || contentType == "text/markdown" {
		return Decision{Kind: KindMarkdown, Inline: true, ContentType: "text/plain; charset=utf-8", MaximumPreviewSize: 2 << 20}
	}
	if strings.HasPrefix(contentType, "text/") || isSourceExtension(extension) {
		return Decision{Kind: KindText, Inline: true, ContentType: "text/plain; charset=utf-8", MaximumPreviewSize: 2 << 20}
	}
	return Decision{Kind: KindDownload, ContentType: safeType(contentType)}
}

func ValidatePreviewSize(decision Decision, size int64) error {
	if !decision.Inline {
		return errors.New("file type is download-only")
	}
	if decision.MaximumPreviewSize > 0 && size > decision.MaximumPreviewSize {
		return errors.New("file is too large for inline preview")
	}
	return nil
}

func safeType(value string) string {
	if value == "" {
		return "application/octet-stream"
	}
	return value
}

func isSourceExtension(extension string) bool {
	switch extension {
	case ".c", ".cc", ".cpp", ".css", ".go", ".h", ".hpp", ".ini", ".java", ".js", ".json", ".jsx", ".log", ".py", ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml":
		return true
	default:
		return false
	}
}
