package main

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/tidwall/gjson"
	"log"
	"net/http"
	"oidc/pkg/apis/options"
	"oidc/pkg/validation"
	"os"
)

func main() {

	content, err := os.ReadFile("data.json")
	if err != nil {
		log.Fatalf("Error reading the file: %v", err)
	}
	jsonData := string(content)

	result := gjson.Parse(jsonData)
	input := gjsonToResultMap(result)

	logger.SetFlags(logger.Lshortfile)

	opts, err := loadLegacyOptions(input)

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

	//r := httptest.NewRequest(http.MethodGet, "/get", nil)
	//
	//w := httptest.NewRecorder()
	//
	//oauthproxy.serveMux.ServeHTTP(w, r)

	//启动一个 http 服务器，监听在 8080 端口
	err = http.ListenAndServe(":80", oauthproxy.serveMux)
	if err != nil {
		logger.Fatalf("ERROR: %v", err)
	}
}

// loadLegacyOptions loads the old toml options using the legacy flag set
// and legacy options struct.
func loadLegacyOptions(input map[string]interface{}) (*options.Options, error) {
	legacyOpts := options.NewLegacyOptions()

	configDecoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToSliceHookFunc(","),
			mapstructure.StringToTimeDurationHookFunc(),
		),
		Result: &legacyOpts,
	})

	err = configDecoder.Decode(input)
	if err != nil {
		fmt.Println(err)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %v", err)
	}

	return opts, nil
}

func gjsonToResultMap(result gjson.Result) map[string]interface{} {
	// 我们需要一个 map 来对应 JSON 对象
	resultMap := make(map[string]interface{})

	// 遍历 JSON 对象的每个成员
	result.ForEach(func(key, value gjson.Result) bool {
		resultMap[key.String()] = gjsonToInterface(value)
		return true // 继续遍历
	})

	return resultMap
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
