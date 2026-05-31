package screenshot

import (
	"bytes"
	"errors"
	"image/jpeg"
)

// decodeJPEGDimensions returns the width and height of a baseline / progressive
// JPEG without decoding pixels. The stdlib image/jpeg decoder is used for its
// SOF parsing; this is cheaper than full decoding because we discard pixels.
func decodeJPEGDimensions(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty JPEG")
	}

	cfg, err := jpeg.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}

	return cfg.Width, cfg.Height, nil
}
