package main

import (
	"encoding/json"
	"os"
)

func loadCursor() (Cursor, error) {
	data, err := os.ReadFile(cursorFile)
	if err != nil {
		return Cursor{}, err
	}
	var c Cursor
	err = json.Unmarshal(data, &c)
	return c, err
}

func saveCursor(c Cursor) error {
	data, _ := json.Marshal(c)
	return os.WriteFile(cursorFile, data, 0o640)
}
