/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package filter

import (
	"os"
	"reflect"
)

func (f *HttpFilter) expandConfigurationStringField(value string) string {

	// Process env vars
	result := CompiledConfigExpansionEnvExpression.ReplaceAllStringFunc(value, func(match string) string {
		submatch := CompiledConfigExpansionEnvExpression.FindStringSubmatch(match)
		key := submatch[1]

		f.logger.Debug("looking for secret in environment variables", "variable", key)
		secret := os.Getenv(key)
		if secret != "" {
			f.logger.Debug("secret found in environment variables", "variable", key, "value", secret)
			return secret
		}

		f.logger.Debug("secret not found in environment variables", "variable", key)
		return match
	})

	// Process generic secrets coming from SDS
	result = CompiledConfigExpansionSdsExpression.ReplaceAllStringFunc(result, func(match string) string {
		submatch := CompiledConfigExpansionSdsExpression.FindStringSubmatch(match)
		key := submatch[1]

		f.logger.Debug("looking for generic secret in SDS secret manager", "secret_name", key)
		secret, secretFound := f.callbacks.SecretManager().GetGenericSecret(key)
		if secretFound {
			f.logger.Debug("generic secret found in SDS secret manager", "secret_name", key, "value", secret)
			return secret
		}

		f.logger.Debug("generic secret not found in SDS secret manager", "secret_name", key)
		return match
	})

	return result
}

// expandConfigurationPlaceholders loop over the configuration fields looking for those being strings.
// When a string is found, call the string expander.
func (f *HttpFilter) expandConfigurationPlaceholders() {

	configValue := reflect.ValueOf(&f.config).Elem()

	for i := 0; i < configValue.NumField(); i++ {
		field := configValue.Field(i)

		// Field is exported? otherwise can not be changed
		if !field.CanSet() {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			currentValue := field.String()

			//
			processedValue := f.expandConfigurationStringField(currentValue)
			field.SetString(processedValue)

		case reflect.Slice:
			// Manage slices of strings
			if field.Type().Elem().Kind() == reflect.String {

				for j := 0; j < field.Len(); j++ {
					element := field.Index(j)
					currentValue := element.String()

					//
					processedValue := f.expandConfigurationStringField(currentValue)
					element.SetString(processedValue)
				}
			}
		default:
			// Nothing happens
		}
	}
}
