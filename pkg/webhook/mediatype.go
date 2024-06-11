package webhook

import (
	"fmt"
)

const (
	mediaTypeFormat = "application/external.dns.webhook+json;"
)

var (
	mediaTypeVersion1      = mediaTypeVersion("1")
	supportedMediaVersions = []string{"1"}
)

type mediaType string

func mediaTypeVersion(v string) mediaType {
	return mediaType(mediaTypeFormat + "version=" + v)
}

func (m mediaType) Is(headerValue string) bool {
	return string(m) == headerValue
}

func checkAndGetMediaTypeHeaderValue(value string) (string, error) {
	for _, v := range supportedMediaVersions {
		if mediaTypeVersion(v).Is(value) {
			return v, nil
		}
	}

	supportedMediaTypesString := ""
	for i, v := range supportedMediaVersions {
		sep := ""
		if i < len(supportedMediaVersions)-1 {
			sep = ", "
		}
		supportedMediaTypesString += string(mediaTypeVersion(v)) + sep
	}
	return "", fmt.Errorf("unsupported media type version: '%s'. supported media types are: '%s'", value, supportedMediaTypesString)
}
