// DO NOT EDIT!
// Code generated by ffjson <https://github.com/pquerna/ffjson>
// source: glog_json.go
// DO NOT EDIT!

package glog

import (
	"bytes"
	"encoding/json"
	"fmt"
	fflib "github.com/pquerna/ffjson/fflib/v1"
)

func (mj *logJSON) MarshalJSON() ([]byte, error) {
	var buf fflib.Buffer
	if mj == nil {
		buf.WriteString("null")
		return buf.Bytes(), nil
	}
	err := mj.MarshalJSONBuf(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (mj *logJSON) MarshalJSONBuf(buf fflib.EncodingBuffer) error {
	if mj == nil {
		buf.WriteString("null")
		return nil
	}
	var err error
	var obj []byte
	_ = obj
	_ = err
	buf.WriteString(`{"@source_host":`)
	fflib.WriteJsonString(buf, string(mj.SourceHost))
	buf.WriteString(`,"@timestamp":`)

	{

		obj, err = mj.TimeStamp.MarshalJSON()
		if err != nil {
			return err
		}
		buf.Write(obj)

	}
	buf.WriteString(`,"@fields":`)
	/* Falling back. type=map[string]interface {} kind=map */
	err = buf.Encode(mj.Fields)
	if err != nil {
		return err
	}
	buf.WriteString(`,"message":`)
	fflib.WriteJsonString(buf, string(mj.Message))
	buf.WriteByte('}')
	return nil
}

const (
	ffj_t_logJSONbase = iota
	ffj_t_logJSONno_such_key

	ffj_t_logJSON_SourceHost

	ffj_t_logJSON_TimeStamp

	ffj_t_logJSON_Fields

	ffj_t_logJSON_Message
)

var ffj_key_logJSON_SourceHost = []byte("@source_host")

var ffj_key_logJSON_TimeStamp = []byte("@timestamp")

var ffj_key_logJSON_Fields = []byte("@fields")

var ffj_key_logJSON_Message = []byte("message")

func (uj *logJSON) UnmarshalJSON(input []byte) error {
	fs := fflib.NewFFLexer(input)
	return uj.UnmarshalJSONFFLexer(fs, fflib.FFParse_map_start)
}

func (uj *logJSON) UnmarshalJSONFFLexer(fs *fflib.FFLexer, state fflib.FFParseState) error {
	var err error = nil
	currentKey := ffj_t_logJSONbase
	_ = currentKey
	tok := fflib.FFTok_init
	wantedTok := fflib.FFTok_init

mainparse:
	for {
		tok = fs.Scan()
		//	println(fmt.Sprintf("debug: tok: %v  state: %v", tok, state))
		if tok == fflib.FFTok_error {
			goto tokerror
		}

		switch state {

		case fflib.FFParse_map_start:
			if tok != fflib.FFTok_left_bracket {
				wantedTok = fflib.FFTok_left_bracket
				goto wrongtokenerror
			}
			state = fflib.FFParse_want_key
			continue

		case fflib.FFParse_after_value:
			if tok == fflib.FFTok_comma {
				state = fflib.FFParse_want_key
			} else if tok == fflib.FFTok_right_bracket {
				goto done
			} else {
				wantedTok = fflib.FFTok_comma
				goto wrongtokenerror
			}

		case fflib.FFParse_want_key:
			// json {} ended. goto exit. woo.
			if tok == fflib.FFTok_right_bracket {
				goto done
			}
			if tok != fflib.FFTok_string {
				wantedTok = fflib.FFTok_string
				goto wrongtokenerror
			}

			kn := fs.Output.Bytes()
			if len(kn) <= 0 {
				// "" case. hrm.
				currentKey = ffj_t_logJSONno_such_key
				state = fflib.FFParse_want_colon
				goto mainparse
			} else {
				switch kn[0] {

				case '@':

					if bytes.Equal(ffj_key_logJSON_SourceHost, kn) {
						currentKey = ffj_t_logJSON_SourceHost
						state = fflib.FFParse_want_colon
						goto mainparse

					} else if bytes.Equal(ffj_key_logJSON_TimeStamp, kn) {
						currentKey = ffj_t_logJSON_TimeStamp
						state = fflib.FFParse_want_colon
						goto mainparse

					} else if bytes.Equal(ffj_key_logJSON_Fields, kn) {
						currentKey = ffj_t_logJSON_Fields
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				case 'm':

					if bytes.Equal(ffj_key_logJSON_Message, kn) {
						currentKey = ffj_t_logJSON_Message
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				}

				if fflib.EqualFoldRight(ffj_key_logJSON_Message, kn) {
					currentKey = ffj_t_logJSON_Message
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.EqualFoldRight(ffj_key_logJSON_Fields, kn) {
					currentKey = ffj_t_logJSON_Fields
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.EqualFoldRight(ffj_key_logJSON_TimeStamp, kn) {
					currentKey = ffj_t_logJSON_TimeStamp
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.EqualFoldRight(ffj_key_logJSON_SourceHost, kn) {
					currentKey = ffj_t_logJSON_SourceHost
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				currentKey = ffj_t_logJSONno_such_key
				state = fflib.FFParse_want_colon
				goto mainparse
			}

		case fflib.FFParse_want_colon:
			if tok != fflib.FFTok_colon {
				wantedTok = fflib.FFTok_colon
				goto wrongtokenerror
			}
			state = fflib.FFParse_want_value
			continue
		case fflib.FFParse_want_value:

			if tok == fflib.FFTok_left_brace || tok == fflib.FFTok_left_bracket || tok == fflib.FFTok_integer || tok == fflib.FFTok_double || tok == fflib.FFTok_string || tok == fflib.FFTok_bool || tok == fflib.FFTok_null {
				switch currentKey {

				case ffj_t_logJSON_SourceHost:
					goto handle_SourceHost

				case ffj_t_logJSON_TimeStamp:
					goto handle_TimeStamp

				case ffj_t_logJSON_Fields:
					goto handle_Fields

				case ffj_t_logJSON_Message:
					goto handle_Message

				case ffj_t_logJSONno_such_key:
					err = fs.SkipField(tok)
					if err != nil {
						return fs.WrapErr(err)
					}
					state = fflib.FFParse_after_value
					goto mainparse
				}
			} else {
				goto wantedvalue
			}
		}
	}

handle_SourceHost:

	/* handler: uj.SourceHost type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.SourceHost = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_TimeStamp:

	/* handler: uj.TimeStamp type=time.Time kind=struct quoted=false*/

	{
		if tok == fflib.FFTok_null {

			state = fflib.FFParse_after_value
			goto mainparse
		}

		tbuf, err := fs.CaptureField(tok)
		if err != nil {
			return fs.WrapErr(err)
		}

		err = uj.TimeStamp.UnmarshalJSON(tbuf)
		if err != nil {
			return fs.WrapErr(err)
		}
		state = fflib.FFParse_after_value
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_Fields:

	/* handler: uj.Fields type=map[string]interface {} kind=map quoted=false*/

	{

		{
			if tok != fflib.FFTok_left_bracket && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for ", tok))
			}
		}

		if tok == fflib.FFTok_null {
			uj.Fields = nil
		} else {

			uj.Fields = make(map[string]interface{}, 0)

			wantVal := true

			for {

				var k string

				var tmp_uj__Fields interface{}

				tok = fs.Scan()
				if tok == fflib.FFTok_error {
					goto tokerror
				}
				if tok == fflib.FFTok_right_bracket {
					break
				}

				if tok == fflib.FFTok_comma {
					if wantVal == true {
						// TODO(pquerna): this isn't an ideal error message, this handles
						// things like [,,,] as an array value.
						return fs.WrapErr(fmt.Errorf("wanted value token, but got token: %v", tok))
					}
					continue
				} else {
					wantVal = true
				}

				/* handler: k type=string kind=string quoted=false*/

				{

					{
						if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
							return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
						}
					}

					if tok == fflib.FFTok_null {

					} else {

						outBuf := fs.Output.Bytes()

						k = string(string(outBuf))

					}
				}

				// Expect ':' after key
				tok = fs.Scan()
				if tok != fflib.FFTok_colon {
					return fs.WrapErr(fmt.Errorf("wanted colon token, but got token: %v", tok))
				}

				tok = fs.Scan()
				/* handler: tmp_uj__Fields type=interface {} kind=interface quoted=false*/

				{
					/* Falling back. type=interface {} kind=interface */
					tbuf, err := fs.CaptureField(tok)
					if err != nil {
						return fs.WrapErr(err)
					}

					err = json.Unmarshal(tbuf, &tmp_uj__Fields)
					if err != nil {
						return fs.WrapErr(err)
					}
				}

				uj.Fields[k] = tmp_uj__Fields

				wantVal = false
			}

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_Message:

	/* handler: uj.Message type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.Message = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

wantedvalue:
	return fs.WrapErr(fmt.Errorf("wanted value token, but got token: %v", tok))
wrongtokenerror:
	return fs.WrapErr(fmt.Errorf("ffjson: wanted token: %v, but got token: %v output=%s", wantedTok, tok, fs.Output.String()))
tokerror:
	if fs.BigError != nil {
		return fs.WrapErr(fs.BigError)
	}
	err = fs.Error.ToError()
	if err != nil {
		return fs.WrapErr(err)
	}
	panic("ffjson-generated: unreachable, please report bug.")
done:
	return nil
}