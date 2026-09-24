package orbit

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Inspect the original JSON before decoding: encoding/json otherwise accepts
// duplicates and null for nonnullable Go fields. Both are unsafe for grants.
func uniqueJSON(data []byte) (any, error) {
	if len(data) == 0 || len(data) > maxBytes || !utf8.Valid(data) {
		return nil, ErrInvalidResponse
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := jsonValue(d, 0)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalidResponse
	}
	return v, nil
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrInvalidResponse
	}
	token, err := d.Token()
	if err != nil {
		return nil, ErrInvalidResponse
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for d.More() {
			t, err := d.Token()
			if err != nil {
				return nil, ErrInvalidResponse
			}
			key, ok := t.(string)
			if !ok {
				return nil, ErrInvalidResponse
			}
			if _, exists := object[key]; exists {
				return nil, ErrInvalidResponse
			}
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if t, err := d.Token(); err != nil || t != json.Delim('}') {
			return nil, ErrInvalidResponse
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for d.More() {
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if t, err := d.Token(); err != nil || t != json.Delim(']') {
			return nil, ErrInvalidResponse
		}
		return array, nil
	default:
		return nil, ErrInvalidResponse
	}
}

func decodeJSON(data []byte, target any) error {
	v, err := uniqueJSON(data)
	if err != nil {
		return err
	}
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Pointer {
		return ErrInvalidResponse
	}
	if err := requiredShape(v, t.Elem()); err != nil {
		return err
	}
	if json.Unmarshal(data, target) != nil {
		return ErrInvalidResponse
	}
	return nil
}

// Wire structs mark optional/nullable fields with pointers. Unknown informational
// fields are ignored; fields declared by this contract retain exact names/types.
func requiredShape(v any, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		if v == nil {
			return nil
		}
		return requiredShape(v, t.Elem())
	}
	if v == nil {
		return ErrInvalidResponse
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := v.(map[string]any)
		if !ok {
			return ErrInvalidResponse
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			for key := range object {
				if key != name && strings.EqualFold(key, name) {
					return ErrInvalidResponse
				}
			}
			if err := requiredShape(object[name], field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		array, ok := v.([]any)
		if !ok {
			return ErrInvalidResponse
		}
		for _, item := range array {
			if err := requiredShape(item, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := v.(map[string]any)
		if !ok {
			return ErrInvalidResponse
		}
		for _, item := range object {
			if err := requiredShape(item, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
