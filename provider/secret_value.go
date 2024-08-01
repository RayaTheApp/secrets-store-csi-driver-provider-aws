package provider

import (
	"encoding/json"
	"fmt"

	"github.com/jmespath/go-jmespath"
	"k8s.io/klog/v2"
)

// Contains the actual contents of the secret fetched from either Secret Manager
// or SSM Parameter Store along with the original descriptor.
type SecretValue struct {
	Value      []byte
	Descriptor SecretDescriptor
}

func (p *SecretValue) String() string { return "<REDACTED>" } // Do not log secrets

// parse out and return specified key value pairs from the secret
func (p *SecretValue) getJsonSecrets() (s []*SecretValue, e error) {
	jsonValues := make([]*SecretValue, 0)

	var data map[string]interface{}
	err := json.Unmarshal(p.Value, &data)
	if err != nil {
		return nil, fmt.Errorf("Invalid JSON used with jmesPath in secret: %s.", p.Descriptor.ObjectName)
	}

	// If SyncAllKeys is enabled, extract all key-value pairs
	if p.Descriptor.SyncAllKeys {
		klog.Infof("SyncAllKeys is enabled for secret: %s", p.Descriptor.ObjectName)

		for key, value := range data {
			// Ensure the value is a string before processing
			valueAsString, _ := value.(string)

			// Create a descriptor for each key-value pair
			descriptor := SecretDescriptor{
				ObjectName:  p.Descriptor.ObjectName,
				ObjectAlias: key,
				ObjectType:  p.Descriptor.ObjectType,
				translate:   p.Descriptor.translate,
				mountDir:    p.Descriptor.mountDir,
			}

			secretValue := SecretValue{
				Value:      []byte(valueAsString),
				Descriptor: descriptor,
			}
			jsonValues = append(jsonValues, &secretValue)
		}
		return jsonValues, nil
	}

	// Process specific JMESPath entries if SyncAllKeys is not enabled
	for _, jmesPathEntry := range p.Descriptor.JMESPath {
		jsonSecret, err := jmespath.Search(jmesPathEntry.Path, data)
		if err != nil {
			return nil, fmt.Errorf("Invalid JMES Path: %s.", jmesPathEntry.Path)
		}

		if jsonSecret == nil {
			return nil, fmt.Errorf("JMES Path - %s for object alias - %s does not point to a valid object.",
				jmesPathEntry.Path, jmesPathEntry.ObjectAlias)
		}

		jsonSecretAsString, isString := jsonSecret.(string)
		if !isString {
			return nil, fmt.Errorf("Invalid JMES search result type for path:%s. Only string is allowed.", jmesPathEntry.Path)
		}

		descriptor := p.Descriptor.getJmesEntrySecretDescriptor(&jmesPathEntry)

		secretValue := SecretValue{
			Value:      []byte(jsonSecretAsString),
			Descriptor: descriptor,
		}
		jsonValues = append(jsonValues, &secretValue)
	}
	return jsonValues, nil
}
