package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const (
	maximumDiffDepth   = 128
	maximumDiffChanges = 10000
)

type jsonChange struct {
	Operation string `json:"operation"`
	Path      string `json:"path"`
	Before    any    `json:"before,omitempty"`
	After     any    `json:"after,omitempty"`
}

func compareJSON(beforeBytes, afterBytes []byte) ([]jsonChange, error) {
	before, err := decodeJSONValue(beforeBytes)
	if err != nil {
		return nil, runtimeError("INVALID_SERVER_RESPONSE", "the source GoalSpec is invalid JSON")
	}
	after, err := decodeJSONValue(afterBytes)
	if err != nil {
		return nil, runtimeError("INVALID_SERVER_RESPONSE", "the target GoalSpec is invalid JSON")
	}
	changes := make([]jsonChange, 0)
	if err := appendJSONChanges(&changes, "", before, after, 0); err != nil {
		return nil, err
	}
	return changes, nil
}

func decodeJSONValue(input []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, runtimeError("INVALID_SERVER_RESPONSE", "multiple JSON values are not allowed")
	}
	return value, nil
}

func appendJSONChanges(changes *[]jsonChange, path string, before, after any, depth int) error {
	if depth > maximumDiffDepth {
		return runtimeError("DIFF_TOO_COMPLEX", "GoalSpec nesting exceeds 128 levels")
	}
	beforeObject, beforeIsObject := before.(map[string]any)
	afterObject, afterIsObject := after.(map[string]any)
	if beforeIsObject && afterIsObject {
		keys := make([]string, 0, len(beforeObject)+len(afterObject))
		seen := make(map[string]struct{}, len(beforeObject)+len(afterObject))
		for key := range beforeObject {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		for key := range afterObject {
			if _, found := seen[key]; !found {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			beforeValue, beforeFound := beforeObject[key]
			afterValue, afterFound := afterObject[key]
			childPath := path + "/" + escapeJSONPointer(key)
			switch {
			case !beforeFound:
				if err := appendJSONChange(changes, jsonChange{Operation: "add", Path: childPath, After: afterValue}); err != nil {
					return err
				}
			case !afterFound:
				if err := appendJSONChange(changes, jsonChange{Operation: "remove", Path: childPath, Before: beforeValue}); err != nil {
					return err
				}
			default:
				if err := appendJSONChanges(changes, childPath, beforeValue, afterValue, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	beforeArray, beforeIsArray := before.([]any)
	afterArray, afterIsArray := after.([]any)
	if beforeIsArray && afterIsArray {
		shared := len(beforeArray)
		if len(afterArray) < shared {
			shared = len(afterArray)
		}
		for index := 0; index < shared; index++ {
			if err := appendJSONChanges(changes, path+"/"+strconv.Itoa(index), beforeArray[index], afterArray[index], depth+1); err != nil {
				return err
			}
		}
		for index := len(beforeArray) - 1; index >= shared; index-- {
			if err := appendJSONChange(changes, jsonChange{Operation: "remove", Path: path + "/" + strconv.Itoa(index), Before: beforeArray[index]}); err != nil {
				return err
			}
		}
		for index := shared; index < len(afterArray); index++ {
			if err := appendJSONChange(changes, jsonChange{Operation: "add", Path: path + "/" + strconv.Itoa(index), After: afterArray[index]}); err != nil {
				return err
			}
		}
		return nil
	}
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if path == "" {
		path = "/"
	}
	return appendJSONChange(changes, jsonChange{Operation: "replace", Path: path, Before: before, After: after})
}

func appendJSONChange(changes *[]jsonChange, change jsonChange) error {
	if len(*changes) >= maximumDiffChanges {
		return runtimeError("DIFF_TOO_COMPLEX", "GoalSpec diff exceeds 10000 changes")
	}
	*changes = append(*changes, change)
	return nil
}

func escapeJSONPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
