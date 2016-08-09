// Go support for leveled logs, analogous to https://code.google.com/p/google-glog/
//
// Modifications copyright 2013 Ernest Micklei. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package glog

import (
	"strconv"
	"time"
)

/*
{
   "@source_host":"test.here.com",
   "@timestamp":"2013-10-24T09:30:46.947024155+02:00",
   "@fields":{
      "level":"INFO",
      "threadid":"400004",
      "file":"file.go",
      "line":10
   },
   "@message":"hello"
}
*/
type logJSON struct {
	SourceHost string                 `json:"@source_host"`
	TimeStamp  time.Time              `json:"@timestamp"`
	Fields     map[string]interface{} `json:"@fields"`
	Message    string                 `json:"message"`
}

// WriteWithStack decodes the data and writes a logstash json event
func WriteWithStack(data []byte, stack []byte) ([]byte, error) {
	logJSON := &logJSON{Fields: make(map[string]interface{})}
	addStaticInfo(logJSON)

	// peek for normal logline
	sev := data[0]
	switch sev {
	case 73, 87, 69, 70: // IWEF
		iwefJSON(sev, data, stack, logJSON)
	default:
		logJSON.Message = string(data)
	}

	return logJSON.MarshalJSON()
}

// openEvent writes the "header" part of the JSON message.
func addStaticInfo(log *logJSON) {
	log.SourceHost = host
	log.TimeStamp = timeNow()
}

var levelKey = "level"
var threadidKey = "threadid"
var fileKey = "file"
var lineKey = "line"
var stackKey = "stack"

// iwefJSON decodes a glog data packet and write the JSON representation.
// [IWEF]mmdd hh:mm:ss.uuuuuu threadid file:line] msg
func iwefJSON(sev byte, data []byte, trace []byte, log *logJSON) {
	switch sev {
	case 73:
		log.Fields[levelKey] = "INFO"
	case 87:
		log.Fields[levelKey] = "WARNING"
	case 69:
		log.Fields[levelKey] = "ERROR"
	case 70:
		log.Fields[levelKey] = "FATAL"
	}
	r := &iwefreader{data, 22} // past last u
	r.skipAllSpace()
	log.Fields[threadidKey] = r.stringUpTo(32)
	r.skip() // space
	log.Fields[fileKey] = r.stringUpTo(58)
	r.skip() // :
	log.Fields[lineKey], _ = strconv.Atoi(r.stringUpTo(93))
	// ]
	r.skip()
	// space
	r.skip()
	if trace != nil && len(trace) > 0 {
		log.Fields[stackKey] = string(trace)
	}
	// extras?
	for k, v := range ExtraFields {
		log.Fields[k] = v
	}
	// fields
	log.Message = r.stringUpToLineEnd()
}

// iwefreader is a small helper object to parse a glog IWEF entry
// ffjson: skip
type iwefreader struct {
	data     []byte
	position int // read offset in data
}

// skip advances the position in data
func (i *iwefreader) skip() {
	i.position++
}

// skip advances the position in data
func (i *iwefreader) skipAllSpace() {
	for i.data[i.position] == 32 {
		i.position++
	}
	return
}

// stringUpToLineEnd returns the string part from the data up to not-including the line end.
func (i iwefreader) stringUpToLineEnd() string {
	return string(i.data[i.position : len(i.data)-1]) // without the line delimiter
}

// stringUpTo returns the string part from the data up to not-including a delimiter.
func (i *iwefreader) stringUpTo(delim byte) string {
	start := i.position
	for i.data[i.position] != delim {
		i.position++
	}
	return string(i.data[start:i.position])
}
