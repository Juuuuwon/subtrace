// Copyright (c) Subtrace, Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tracer

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/google/martian/v3/har"
	"subtrace.dev/cmd/run/journal"
	"subtrace.dev/event"
	"subtrace.dev/filter"
	"subtrace.dev/global"
	"subtrace.dev/stats"
)

var PayloadLimitBytes int64 = 4096 // bytes

type Parser struct {
	global *global.Global
	event  *event.Event

	wg       sync.WaitGroup
	errs     chan error
	begin    time.Time
	timings  har.Timings
	request  *har.Request
	response *har.Response

	journalIdx uint64
}

func NewParser(global *global.Global, event *event.Event) *Parser {
	var journalIdx uint64
	if journal.Enabled {
		journalIdx = global.Journal.GetIndex()
	}

	return &Parser{
		global: global,
		event:  event,

		errs:  make(chan error, 2),
		begin: time.Now().UTC(),

		journalIdx: journalIdx,
	}
}

func (p *Parser) UseRequest(req *http.Request) {
	sampler := newSampler(req.Body)
	req.Body = sampler

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		h, err := har.NewRequest(req, false)
		if err != nil {
			p.errs <- fmt.Errorf("parse HAR request: %w", err)
			return
		}

		for i := range h.Headers {
			switch strings.ToLower(h.Headers[i].Name) {
			case "authorization", "cookie":
				h.Headers[i].Value = p.global.Config.SantizeCredential(h.Headers[i].Value)
			}
		}

		start := time.Now()
		if err := <-sampler.errs; err != nil {
			p.errs <- fmt.Errorf("read request body: %w", err)
			return
		}
		p.timings.Send = time.Since(start).Milliseconds()

		text := sampler.data[:sampler.used]
		switch req.Header.Get("content-encoding") {
		case "gzip":
			gr, err := gzip.NewReader(bytes.NewBuffer(text))
			if err != nil {
				p.errs <- fmt.Errorf("create gzip reader: %w", err)
				return
			}
			if raw, err := io.ReadAll(gr); err != nil {
				p.errs <- fmt.Errorf("read gzip: %w", err)
				return
			} else {
				text = raw
			}
		case "br":
			if raw, err := io.ReadAll(brotli.NewReader(bytes.NewBuffer(text))); err != nil {
				p.errs <- fmt.Errorf("decode brotli: %w", err)
				return
			} else {
				text = raw
			}
		}

		h.PostData = &har.PostData{
			MimeType: req.Header.Get("content-type"),
			Text:     string(text),
		}

		p.request = h
		p.errs <- nil
	}()
}

func (p *Parser) UseResponse(resp *http.Response) {
	sampler := newSampler(resp.Body)
	resp.Body = sampler

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		start := time.Now()

		h, err := har.NewResponse(resp, false)
		if err != nil {
			p.errs <- fmt.Errorf("parse HAR response: %w", err)
			return
		}

		// TODO: does the "wait" timer start before or after the request is fully
		// sent (including body)?
		p.timings.Wait = time.Since(start).Milliseconds()

		for i := range h.Headers {
			switch strings.ToLower(h.Headers[i].Name) {
			case "set-cookie":
				h.Headers[i].Value = p.global.Config.SantizeCredential(h.Headers[i].Value)
			}
		}

		start = time.Now()
		if err := <-sampler.errs; err != nil {
			p.errs <- fmt.Errorf("parse HAR response: %w", err)
			return
		}
		p.timings.Receive = time.Since(start).Milliseconds()

		text := sampler.data[:sampler.used]
		switch resp.Header.Get("content-encoding") {
		case "gzip":
			gr, err := gzip.NewReader(bytes.NewBuffer(text))
			if err != nil {
				p.errs <- fmt.Errorf("create gzip reader: %w", err)
				return
			}
			if raw, err := io.ReadAll(gr); err != nil {
				p.errs <- fmt.Errorf("read gzip: %w", err)
				return
			} else {
				text = raw
			}
		case "br":
			if raw, err := io.ReadAll(brotli.NewReader(bytes.NewBuffer(text))); err != nil {
				p.errs <- fmt.Errorf("decode brotli: %w", err)
				return
			} else {
				text = raw
			}
		}

		h.Content = &har.Content{
			Size:     sampler.used,
			MimeType: resp.Header.Get("content-type"),
			Text:     text,
			Encoding: "base64",
		}

		p.response = h
		p.errs <- nil
	}()
}

func (p *Parser) include(tags map[string]string, entry *har.Entry) bool {
	begin := time.Now()
	defer func() {
		slog.Debug("evaluated filters", "eventID", p.event.Get("event_id"), "took", time.Since(begin).Round(time.Microsecond))
	}()

	f, err := p.global.Config.GetMatchingFilter(tags, entry)
	if err != nil {
		// fall back to tracing the request if filter eval fails
		return true
	}
	if f == nil {
		return true
	}

	switch f.Action {
	case filter.ActionInclude:
		return true
	case filter.ActionExclude:
		return false
	default:
		panic(fmt.Errorf("unknown filter action %q", f.Action))
	}
}

func (p *Parser) Finish() error {
	p.wg.Wait()
	if err := errors.Join(<-p.errs, <-p.errs); err != nil {
		return err
	}

	var loglines []string
	if journal.Enabled {
		loglines = p.global.Journal.CopyFrom(p.journalIdx)
	}

	entry := &har.Entry{
		ID:              p.event.Get("event_id"),
		StartedDateTime: p.begin.UTC(),
		Time:            time.Since(p.begin).Milliseconds(),
		Request:         p.request,
		Response:        p.response,
		Timings:         &p.timings,
	}

	for k, v := range stats.Load() {
		p.event.Set(k, v)
	}

	tags := p.event.Map()

	if !p.include(tags, entry) {
		return nil
	}

	json, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	if p.global.Devtools != nil && p.global.Devtools.HijackPath != "" {
		go p.global.Devtools.Send(json)
		return nil
	}

	var sendReflector, sendTunneler bool
	switch strings.ToLower(os.Getenv("SUBTRACE_REFLECTOR")) {
	case "1", "t", "true", "y", "yes":
		sendReflector, sendTunneler = true, false
	case "0", "f", "false", "n", "no":
		sendReflector, sendTunneler = false, true
	case "both":
		sendReflector, sendTunneler = true, true
	default:
		sendReflector, sendTunneler = true, false
	}
	if sendReflector {
		if err := p.sendReflector(tags, json, loglines); err != nil {
			slog.Error("failed to publish event to reflector", "eventID", p.event.Get("event_id"), "err", err)
		}
	}
	if sendTunneler {
		ev := p.event.Copy()
		ev.Set("http_har_entry", base64.RawStdEncoding.EncodeToString(json))
		DefaultManager.Insert(ev.String())
	}
	return nil
}

// 수정 ------------------------------------------------------------------------------------------------------------------------------------
var once sync.Once
var sloThreshold float64
var logStreamName string
var logGroupName string
var (
	cfg    aws.Config
	client *cloudwatchlogs.Client
	err    error
)

func init() {
	cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion(os.Getenv("AWS_REGION_NAME")))
	if err != nil {
		log.Fatalf("AWS 설정 로드 실패: %v", err)
	}

	client = cloudwatchlogs.NewFromConfig(cfg)
	logGroupName = "/proxy-logging"

	sloThreshold = 200.0 // 기본값
	if sloStr := os.Getenv("SLO"); sloStr != "" {
		if val, err := strconv.ParseFloat(sloStr, 64); err == nil {
			sloThreshold = val
		}
	}
}

func transformJSON(tags map[string]string, input []byte) []byte {
	// JSON을 map으로 파싱
	var data map[string]interface{}
	if err := json.Unmarshal(input, &data); err != nil {
		return nil
	}

	// 1. 지정된 필드 제거
	delete(data, "cache")
	if request, ok := data["request"].(map[string]interface{}); ok {
		delete(request, "bodySize")
		delete(request, "headersSize")
		delete(request, "httpVersion")
	}
	if response, ok := data["response"].(map[string]interface{}); ok {
		delete(response, "bodySize")
		delete(response, "headersSize")
		delete(response, "httpVersion")
		delete(response, "statusText")
	}
	delete(data, "startedDateTime")
	delete(data, "timings")

	// "time"을 "A-time"으로 변경
	if timeVal, ok := data["time"]; ok {
		data["A-time"] = timeVal
		delete(data, "time")
	}

	// 2. headers와 queryString을 map[string]string 형태로 변환
	if request, ok := data["request"].(map[string]interface{}); ok {
		if headers, ok := request["headers"].([]interface{}); ok {
			headerMap := make(map[string]string)
			for _, h := range headers {
				if header, ok := h.(map[string]interface{}); ok {
					name := header["name"].(string)
					value := header["value"].(string)
					headerMap[name] = value
				}
			}
			request["headers"] = headerMap
		}
		if queryString, ok := request["queryString"].([]interface{}); ok {
			queryMap := make(map[string]string)
			for _, q := range queryString {
				if query, ok := q.(map[string]interface{}); ok {
					name := query["name"].(string)
					value := query["value"].(string)
					queryMap[name] = value
				}
			}
			request["queryString"] = queryMap
		}

		if url, ok := request["url"].(string); ok {
			request["parsed_url"] = strings.Split(url, "?")[0]
		}
	}

	if response, ok := data["response"].(map[string]interface{}); ok {
		if headers, ok := response["headers"].([]interface{}); ok {
			headerMap := make(map[string]string)
			for _, h := range headers {
				if header, ok := h.(map[string]interface{}); ok {
					name := header["name"].(string)
					value := header["value"].(string)
					headerMap[name] = value
				}
			}
			response["headers"] = headerMap
		}
	}

	// 3. status가 2xx가 아닐 때 또는 A-time이 SLO보다 클 때 .status-error, .slo-violation 추가
	if response, ok := data["response"].(map[string]interface{}); ok {
		if status, ok := response["status"].(float64); ok {
			if status < 200 || status >= 300 {
				data["status-error"] = status
			}
		}
		if aTime, ok := data["A-time"].(float64); ok {
			if aTime > sloThreshold {
				data["slo-violation"] = aTime
			}
		}
	}

	// 4. .curl 필드 추가
	if request, ok := data["request"].(map[string]interface{}); ok {
		method := request["method"].(string)
		urlStr := request["url"].(string)
		headers := request["headers"].(map[string]string)
		var curlParts []string

		if method == "POST" {
			if postData, ok := request["postData"].(map[string]interface{}); ok {
				if text, ok := postData["text"].(string); ok {
					curlParts = append(curlParts, fmt.Sprintf("-d '%s'", text))
				}
			}
		}
		curlParts = append(curlParts, fmt.Sprintf("'%s'", urlStr))
		for name, value := range headers {
			if name != "Content-Length" && name != "Host" {
				curlParts = append(curlParts, fmt.Sprintf("-H '%s'", fmt.Sprintf("%s: %s", name, value)))
			}
		}
		curlParts = append(curlParts, fmt.Sprintf("-X %s", method))
		sort.Strings(curlParts)
		curl := "curl " + strings.Join(curlParts, " ")
		data["A-curl"] = curl

		// 5. .request.path 필드 추가
		parsedURL, err := url.Parse(urlStr)
		if err == nil {
			request["path"] = parsedURL.Path
		}
	}

	// 6. .response.content.encoding == base64일 때 디코딩 처리
	if response, ok := data["response"].(map[string]interface{}); ok {
		if content, ok := response["content"].(map[string]interface{}); ok {
			if encoding, ok := content["encoding"].(string); ok && encoding == "base64" {
				if text, ok := content["text"].(string); ok {
					decoded, err := base64.StdEncoding.DecodeString(text)
					if err == nil {
						response["text"] = string(decoded)
					}
					delete(response, "content")
				}
			}
		}
	}

	// 7. tags에서 process_executable_name을 JSON에 추가
	if processName, ok := tags["process_executable_name"]; ok {
		data["_process_executable_name"] = processName
	}

	// 변환된 데이터를 JSON으로 직렬화
	output, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	return output
}


func CreateLogStream(tags map[string]string) {
	once.Do(func() {
		now := time.Now()
		timeString := now.Format("15.04.05")

		logGroupName = "/proxy-logging"
		logStreamName = fmt.Sprintf("%s -- %s", strings.Split(tags["process_command_line"], " ")[0], timeString)
		_, err = client.CreateLogStream(context.TODO(), &cloudwatchlogs.CreateLogStreamInput{
			LogGroupName:  &logGroupName,
			LogStreamName: &logStreamName,
		})
		if err != nil {
			log.Fatalf("subtrace: 로그 스트림 생성 실패: %v\n", err)
		}
		fmt.Printf("subtrace: 로그 스트림 생성 성공")
	})
}

func (p *Parser) sendReflector(tags map[string]string, json []byte, loglines []string) error {
	CreateLogStream(tags);
	logEvent := types.InputLogEvent{
        Message:   aws.String(string(transformJSON(tags, json))),
        Timestamp: aws.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
    }

    _, err = client.PutLogEvents(context.TODO(), &cloudwatchlogs.PutLogEventsInput{
        LogGroupName:  aws.String(logGroupName),
        LogStreamName: aws.String(logStreamName),
        LogEvents:     []types.InputLogEvent{logEvent},
    })

    if err != nil {
        return fmt.Errorf("subtrace: 로그 이벤트 전송 실패: %w", err)
    }

	return nil
}

type sampler struct {
	orig io.ReadCloser
	errs chan error
	used int64
	data []byte
}

func newSampler(orig io.ReadCloser) *sampler {
	return &sampler{
		orig: orig,
		errs: make(chan error, 1),
		data: make([]byte, PayloadLimitBytes),
	}
}

func (s *sampler) setError(err error) {
	if errors.Is(err, io.EOF) {
		err = nil
	}

	select {
	case s.errs <- err:
	default:
	}
}

func (s *sampler) Read(b []byte) (int, error) {
	n, err := s.orig.Read(b)
	if err != nil {
		s.setError(err)
	}

	if n > 0 && s.used < PayloadLimitBytes {
		c := int64(n)
		if s.used+c > PayloadLimitBytes {
			c = PayloadLimitBytes - s.used
		}
		s.used += int64(copy(s.data[s.used:s.used+c], b[0:c]))
	}
	return n, err
}

func (s *sampler) Close() error {
	err := s.orig.Close()
	s.setError(err)
	return err
}
