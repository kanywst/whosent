package ui

import (
	"reflect"
	"strings"

	"github.com/kanywst/whosent/internal/termsafe"
)

// scrub neutralises every string reachable from v, which must be a pointer,
// in place. The view calls it on everything an adapter hands over (a chain,
// an answer, a form's fields) the moment it arrives.
//
// Rendering also cleans what it draws, but a renderer that forgot would hand
// the terminal to whoever wrote the token, and an adapter adds strings in
// places no renderer has seen yet. Walking the value by reflection means a
// field added to the model tomorrow is covered without anyone remembering
// to cover it. Interface fields (an adapter's Native report) are left
// alone: the view never draws them. So are fields tagged `whosent:"raw"`:
// opaque handles the view passes back to the adapter (a link's revocation
// identifier) and never draws, which scrubbing would stop matching. Fields
// tagged `whosent:"lines"` hold several lines (a JSON document, source
// code): each line is scrubbed on its own and the line breaks kept, because
// every renderer of such a field splits on them before it draws.
func scrub(v any) {
	scrubValue(reflect.ValueOf(v))
}

func scrubValue(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			scrubValue(v.Elem())
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				continue
			}
			switch t.Field(i).Tag.Get("whosent") {
			case "raw":
				continue
			case "lines":
				if f.Kind() == reflect.String {
					lines := strings.Split(f.String(), "\n")
					for k, l := range lines {
						lines[k] = termsafe.Text(l)
					}
					f.SetString(strings.Join(lines, "\n"))
					continue
				}
			}
			scrubValue(f)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			scrubValue(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() || v.Type().Key().Kind() != reflect.String {
			return
		}
		clean := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(iter.Value())
			scrubValue(val)
			clean.SetMapIndex(reflect.ValueOf(termsafe.Text(iter.Key().String())).Convert(v.Type().Key()), val)
		}
		if v.CanSet() {
			v.Set(clean)
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(termsafe.Text(v.String()))
		}
	}
}
