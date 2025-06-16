package protocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/protocol"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/zeromicro/go-zero/core/codec"
	"log"
	"reflect"
	"strconv"
	"strings"
	"time"
)

/*
@Time : 		2022/9/21 9:47
@Author : 		KyoUK4n
@File :			fast
@Software:		GOLAND
@Description:	fast converter
*/

const (
	LogstoreKeyEnvTag = "_fast_logstore_key_"
	EnvCodeTag        = "_fast_env_code_"
	TenantCodeTag     = "_fast_tenant_code_"
	ProductCodeTag    = "_fast_product_code_"
	LogstoreIdTag     = "_fast_logstore_id_"
	ComponentCodeTag  = "_fast_component_code_"

	LogSource          = "_fast_log_source_"
	LogSourceContainer = "container"
)

const (
	EXTERNAL_OVERWRITE_POLICY_DEFAULT = iota // overwrite only when origin key don't exist or origin value is nil
	EXTERNAL_OVERWRITE_POLICY_IFZERO         // overwrite when original value don't exist or is nil or zero-value
	EXTERNAL_OVERWRITE_POLICY_ALWAYS         // always overwrite event original value is not nil
)

const CollectorAesDefaultKey = "af9dv72fc3af146e"

func DecodeReportAccessKey(accessKey string) (string, string, int64, error) {

	if strings.TrimSpace(accessKey) == "" {
		return "", "", 0, errors.New("empty access key")
	}

	decodeString, err := base64.URLEncoding.DecodeString(accessKey)
	if err != nil {
		log.Printf("decode report access key from base64 failed, cause by: %+v", err)
		return "", "", 0, err
	}
	decrypt, err := codec.EcbDecrypt([]byte(CollectorAesDefaultKey), decodeString)
	if err != nil {
		log.Printf("decode report access key by aes failed, cause by: %+v", err)
		return "", "", 0, err
	}

	split := strings.Split(string(decrypt), "|")
	if len(split) != 3 {
		log.Printf("invalid access key: %s", accessKey)
		return "", "", 0, err
	}
	logstoreId, err := strconv.ParseInt(split[2], 10, 64)
	if err != nil {
		log.Printf("invalid logstoreId: %s", split[2])
		return "", "", 0, err
	}
	return split[0], split[1], logstoreId, nil
}

type FastKey struct {
	LogstoreKey   string
	EnvCode       string
	ComponentCode string
	EventTime     int64
}

const (
	TagPrefix     = "__tag__:"
	PathTag       = "_path_"
	SourceTag     = "_source_"
	SourceStdout  = "stdout"
	SourceStderr  = "stderr"
	SourceFileLog = "file_log"
	TimeTag       = "_time_"
	EventTimeTag  = "__event_time__"
)

// ExtractLog parse the log key-value pair into a map structure, also decode fast_logstore_key to [tenantCode, logstoreId]
func ExtractLog(log *protocol.Log, ctx context.Context, alarmType string, writer *jsoniter.Stream) (*FastKey, *jsoniter.Stream) {
	fastKey := &FastKey{}
	var err error

	for _, c := range log.Contents {

		c.Key = TrimFix(c.Key)
		// set _source_ filed to `file_log`
		if strings.Contains(c.Key, PathTag) {
			writer.WriteObjectField(SourceTag)
			writer.WriteString(SourceFileLog)
			_, _ = writer.Write([]byte{','})
		}

		// set logstore key
		if strings.Contains(c.Key, LogstoreKeyEnvTag) && c.Value != "" {
			fastKey.LogstoreKey = c.Value
		}

		// set component code
		if strings.Contains(c.Key, ComponentCodeTag) {
			fastKey.ComponentCode = c.Value
		}

		// fast will write env_code automatically , write in flusher is unnecessary
		if strings.Contains(c.Key, EnvCodeTag) {
			fastKey.EnvCode = c.Value
		}

		if c.Key == TimeTag {
			fastKey.EventTime, err = ParseTime(c.Value)
			if err != nil {
				logger.Errorf(ctx, alarmType, "parse [%s = %s] failed: %+v", TimeTag, c.Value, err)
			}
			continue
		}

		// write field
		writer.WriteObjectField(c.Key)
		writer.WriteString(c.Value)
		_, _ = writer.Write([]byte{','})
	}

	writer.WriteObjectField(TimeTag)
	if fastKey.EventTime <= 0 {
		fastKey.EventTime = time.Now().UnixNano()
	}
	writer.WriteInt64(fastKey.EventTime)
	_, _ = writer.Write([]byte{','})

	return fastKey, writer
}

func writeFastTag(writer *jsoniter.Stream, tenantCode string, productCode string, logstoreId int64) {
	// write tenant_code
	writer.WriteObjectField(TenantCodeTag)
	writer.WriteString(tenantCode)
	_, _ = writer.Write([]byte{','})

	// write product_code
	writer.WriteObjectField(ProductCodeTag)
	writer.WriteString(productCode)
	_, _ = writer.Write([]byte{','})

	// write logstore_id
	writer.WriteObjectField(LogstoreIdTag)
	writer.WriteInt64(logstoreId)
	_, _ = writer.Write([]byte{','})
}

// TrimFix trim suffix and prefix
func TrimFix(key string) string {

	key = strings.TrimPrefix(key, "__tag__:")

	if strings.HasPrefix(key, "__") {
		key = strings.TrimPrefix(key, "_")
	}

	if strings.HasSuffix(key, "__") {
		key = strings.TrimSuffix(key, "_")
	}

	return key
}

// ParseTime parse time string to unix
func ParseTime(str string) (int64, error) {
	dt, err := time.Parse(time.RFC3339Nano, str)
	if err != nil {
		return time.Now().UnixNano(), err
	}

	return dt.UnixNano(), nil
}

func (c *Converter) ConvertToFastProtocolStream(logGroup *protocol.LogGroup, targetFields []string) ([][]byte, []map[string]string, error) {
	convertedLogs, desiredValues, err := c.ConvertToFastProtocolLogs(logGroup, targetFields)
	if err != nil {
		return nil, nil, err
	}

	marshaledLogs := make([][]byte, len(logGroup.Logs))
	for i, log := range convertedLogs {
		switch c.Encoding {
		case EncodingJSON:
			b, err := json.Marshal(log)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to marshal log: %v", log)
			}
			marshaledLogs[i] = b
		default:
			return nil, nil, fmt.Errorf("unsupported encoding format: %s", c.Encoding)
		}
	}
	return marshaledLogs, desiredValues, nil
}

func (c *Converter) setExternalKeyVal(oriMap map[string]interface{}) map[string]interface{} {
	if c.ExternalKeyVal != nil {
		for k, v := range c.ExternalKeyVal {
			oriv, ok := oriMap[k]
			switch c.ExternalOverwritePolicy {
			case EXTERNAL_OVERWRITE_POLICY_DEFAULT:
				if !ok || oriv == nil {
					oriMap[k] = v
				}
			case EXTERNAL_OVERWRITE_POLICY_IFZERO:
				if !ok || oriv == nil {
					oriMap[k] = v
					continue
				}
				if ok && oriv != nil && oriv == reflect.Zero(reflect.TypeOf(oriv)).Interface() {
					oriMap[k] = v
				}
			case EXTERNAL_OVERWRITE_POLICY_ALWAYS:
				oriMap[k] = v
			}
		}
	}
	return oriMap
}

func (c *Converter) isValidLog(fastKey *FastKey) bool {
	flag := false
	if strings.TrimSpace(fastKey.LogstoreKey) == "" {
		if c.ExternalKeyVal != nil {
			logstoreKeyVal, ok := c.ExternalKeyVal[LogstoreKeyEnvTag]
			if ok && logstoreKeyVal != nil {
				logstoreKey, ok := logstoreKeyVal.(string)
				if ok && strings.TrimSpace(logstoreKey) != "" {
					fastKey.LogstoreKey = logstoreKey
					flag = true
				}
			}
		}
	} else {
		flag = true
	}
	return flag
}

func (c *Converter) ConvertToFastProtocolLogs(logGroup *protocol.LogGroup, targetFields []string) ([]map[string]interface{}, []map[string]string, error) {
	convertedLogs, desiredValues := make([]map[string]interface{}, len(logGroup.Logs)), make([]map[string]string, len(logGroup.Logs))

	for i, log := range logGroup.Logs {
		fastMap, fastKey := convertLogToFastMap(log, logGroup.LogTags, logGroup.Source)

		if !c.isValidLog(fastKey) {
			logger.Warningf(context.Background(), "FAST_CONVERT", "empty logstore_key, data dropped: %v", log)
			continue
		}

		fastMap = c.setExternalKeyVal(fastMap)

		convertedLogs[i] = fastMap

		// set fast fields
		desiredValues[i] = map[string]string{
			LogstoreKeyEnvTag: fastKey.LogstoreKey,
			EnvCodeTag:        fastKey.EnvCode,
			ComponentCodeTag:  fastKey.ComponentCode,
		}
	}

	return convertedLogs, desiredValues, nil
}

func convertLogToFastMap(log *protocol.Log, logTags []*protocol.LogTag, source string) (map[string]interface{}, *FastKey) {
	contents := make(map[string]interface{})
	fastKey := &FastKey{}
	var err error
       //ctx := context.Background()
       //logger.Info(ctx,logTags, source)

	for _, logContent := range log.Contents {

		logContent.Key = TrimFix(logContent.Key)
		// set _source_ filed to `file_log`
		if strings.Contains(logContent.Key, PathTag) {
			contents[SourceTag] = SourceFileLog
		}

		// set logstore key
		if strings.Contains(logContent.Key, LogstoreKeyEnvTag) && logContent.Value != "" {
			fastKey.LogstoreKey = logContent.Value
		}

		// set component code
		if strings.Contains(logContent.Key, ComponentCodeTag) {
			fastKey.ComponentCode = logContent.Value
		}

		// fast will write env_code automatically , write in flusher is unnecessary
		if strings.Contains(logContent.Key, EnvCodeTag) {
			fastKey.EnvCode = logContent.Value
		}

		// set __event_time__ field
		if logContent.Key == TimeTag {
			fastKey.EventTime, err = ParseTime(logContent.Value)
			if err != nil {
				logger.Errorf(context.TODO(), "CONVERTER_FAST_ALARM", "parse [%s = %s] failed: %+v", TimeTag, logContent.Value, err)
			}
			continue
		}

		// set field
		contents[logContent.Key] = logContent.Value
	}

	// set _time_ field
	if fastKey.EventTime <= 0 {
		fastKey.EventTime = time.Now().UnixNano()
	}
	contents[TimeTag] = fastKey.EventTime

	// set FAST field
	//contents = setFastField(fastKey, contents)
	contents = setTagsField(contents, logTags, source)
        

	return contents, fastKey
}

func setFastField(fastKey *FastKey, contents map[string]interface{}) map[string]interface{} {
	contents[ComponentCodeTag] = fastKey.ComponentCode
	contents[LogstoreKeyEnvTag] = fastKey.LogstoreKey
	contents[EnvCodeTag] = fastKey.EnvCode

	return contents
}

func setTagsField(contents map[string]interface{}, logTags []*protocol.LogTag, source string) map[string]interface{} {
	for _, logTag := range logTags {
		logTag.Key = TrimFix(logTag.Key)
		contents[logTag.Key] = logTag.Value
	}
	contents["source"] = source
	return contents
}
