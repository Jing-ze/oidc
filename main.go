package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/tidwall/gjson"
	"log"
	"net/http"
	"net/http/httptest"
	"oidc/pkg/apis/options"
	"oidc/pkg/validation"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/spf13/pflag"
)

//func helloHandler(w http.ResponseWriter, r *http.Request) {
//	proxywasm.SendHttpResponse(200, nil, []byte("hello"), -1)
//}
//
//func aboutHandler(w http.ResponseWriter, r *http.Request) {
//	proxywasm.SendHttpResponse(200, nil, []byte("about"), -1)
//}

func main() {

	content, err := os.ReadFile("data.json")
	if err != nil {
		log.Fatalf("Error reading the file: %v", err)
	}
	jsonData := string(content)

	result := gjson.Parse(jsonData)
	jsonBuffer := gjsonToJsonBuffer(result)

	logger.SetFlags(logger.Lshortfile)

	configFlagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ContinueOnError)

	// Because we parse early to determine alpha vs legacy config, we have to
	// ignore any unknown flags for now
	configFlagSet.ParseErrorsWhitelist.UnknownFlags = true

	opts, err := loadLegacyOptions(jsonBuffer, configFlagSet, []string{})
	//opts.Cookie.Secret = "_R-RbKbVucnBjQ6D-C2DLZqXqF0mq7ufMjcMiGbUNqQ="

	if err != nil {
		logger.Fatalf("ERROR: %v", err)
	}

	if err = validation.Validate(opts); err != nil {
		logger.Fatalf("%s", err)
	}

	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy, err := NewOAuthProxy(opts, validator)
	if err != nil {
		logger.Fatalf("ERROR: Failed to initialise OAuth2 Proxy: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/get", nil)

	w := httptest.NewRecorder()

	oauthproxy.serveMux.ServeHTTP(w, r)

	//启动一个 http 服务器，监听在 8080 端口
	//err = http.ListenAndServeTLS(":443", "./ca.crt", "./ca.key", oauthproxy.serveMux)
	//if err != nil {
	//	logger.Fatalf("ERROR: %v", err)
	//}

	// wrapper.SetCtx(
	// 	// 插件名称
	// 	"my-plugin",
	// 	// 为解析插件配置，设置自定义函数
	// 	wrapper.ParseConfigBy(parseConfig),
	// 	// 为处理请求头，设置自定义函数
	// 	wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	// )
}

// loadLegacyOptions loads the old toml options using the legacy flag set
// and legacy options struct.
func loadLegacyOptions(jsonBuffer []byte, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	optionsFlagSet := options.NewLegacyFlagSet()
	optionsFlagSet.AddFlagSet(extraFlags)
	if err := optionsFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	legacyOpts := options.NewLegacyOptions()
	if err := options.Load(jsonBuffer, optionsFlagSet, legacyOpts); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %v", err)
	}

	return opts, nil
}

//// 自定义插件配置
//type MyConfig struct {
//	mockEnable bool
//}
//
//// 在控制台插件配置中填写的yaml配置会自动转换为json，此处直接从json这个参数里解析配置即可
//func parseConfig(json gjson.Result, config *MyConfig, log wrapper.Log) error {
//	// 解析出配置，更新到config中
//	config.mockEnable = json.Get("mockEnable").Bool()
//	return nil
//}
//
//func onHttpRequestHeaders(ctx wrapper.HttpContext, config MyConfig, log wrapper.Log) types.Action {
//	mux := http.NewServeMux()
//	mux.HandleFunc("/hello", helloHandler)
//	mux.HandleFunc("/about", aboutHandler)
//
//	headers, _ := proxywasm.GetHttpRequestHeaders()
//	url := "/"
//	for _, header := range headers {
//		if header[0] == ":path" {
//			url = header[1]
//		}
//	}
//	req, _ := http.NewRequest("GET", url, nil)
//	mux.ServeHTTP(nil, req)
//
//	// 构建表达头部字段的字符串
//	// var headerStr string
//	// for _, header := range headers {
//	// 	headerStr += header[0] + ": " + header[1] + "\r\n"
//	// }
//
//	// if config.mockEnable {
//	// 	proxywasm.SendHttpResponse(200, nil, []byte(headerStr), -1)
//	// }
//	return types.ActionContinue
//}

func gjsonToJsonBuffer(result gjson.Result) []byte {
	// 我们需要一个 map 来对应 JSON 对象
	resultMap := make(map[string]interface{})

	// 遍历 JSON 对象的每个成员
	result.ForEach(func(key, value gjson.Result) bool {
		resultMap[key.String()] = gjsonToInterface(value)
		return true // 继续遍历
	})

	// 有了 resultMap，我们可以序列化为 JSON 字节切片
	jsonBuffer := new(bytes.Buffer)
	encoder := json.NewEncoder(jsonBuffer)
	err := encoder.Encode(resultMap)
	if err != nil {
		log.Fatalf("Error encoding resultMap to JSON: %v", err)
	}
	return jsonBuffer.Bytes()
}

// gjsonToInterface 将 gjson.Result 转换为 interface{}
func gjsonToInterface(result gjson.Result) interface{} {
	switch {
	case result.IsArray():
		// Result 是一个数组，转换每个元素
		values := result.Array()
		array := make([]interface{}, len(values))
		for i, value := range values {
			array[i] = gjsonToInterface(value)
		}
		return array
	case result.IsObject():
		// Result 是一个对象，转换每个成员
		objMap := make(map[string]interface{})
		result.ForEach(func(key, value gjson.Result) bool {
			objMap[key.String()] = gjsonToInterface(value)
			return true // 继续遍历
		})
		return objMap
	default:
		// 为空或为其他复杂类型
		return result.Value()
	}
}
