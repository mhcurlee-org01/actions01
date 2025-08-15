package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	// Read YAML from stdin
	yamlData, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}

	// Parse YAML into a generic map
	var obj interface{}
	if err := yaml.Unmarshal(yamlData, &obj); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing YAML: %v\n", err)
		os.Exit(1)
	}

	// Convert YAML maps from map[interface{}]interface{} to map[string]interface{}
	obj = convertKeys(obj)

	// Encode as JSON
	jsonData, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonData))
}

// convertKeys recursively converts YAML map keys to strings
func convertKeys(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := make(map[string]interface{})
		for k, v := range x {
			m2[fmt.Sprintf("%v", k)] = convertKeys(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convertKeys(v)
		}
	}
	return i
}
