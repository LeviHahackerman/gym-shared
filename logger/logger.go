package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

func InitLogger(env string) zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	var logContext zerolog.Context

	if env == "development" {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		logContext = zerolog.New(consoleWriter).With().Timestamp()
	} else {
		logContext = zerolog.New(os.Stdout).With().Timestamp()
	}

	logger := logContext.Logger()

	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	return logger
}
