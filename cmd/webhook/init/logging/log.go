package logging

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

func Init() {
	setLogLevel()
	setLogFormat()
}

func setLogFormat() {
	format := os.Getenv("LOG_FORMAT")
	if strings.EqualFold(format, "text") {
		log.SetFormatter(&log.TextFormatter{})
	} else {
		log.SetFormatter(&log.JSONFormatter{})
	}
}

func setLogLevel() {
	level := os.Getenv("LOG_LEVEL")
	switch {
	case strings.EqualFold(level, "debug"):
		log.SetLevel(log.DebugLevel)
	case strings.EqualFold(level, "info"):
		log.SetLevel(log.InfoLevel)
	case strings.EqualFold(level, "warn"):
		log.SetLevel(log.WarnLevel)
	case strings.EqualFold(level, "error"):
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}
