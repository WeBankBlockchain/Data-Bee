/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.codegen.constants;

/**
 * ConfigFileConstants 
 *
 * @Description: ConfigFileConstants
 * @author graysonzhang
 * @data 2018-12-17 21:40:55
 *
 */
public class ConfigFileConstants {
	
	/** @Fields GENERATED_APPLICATION_PROPERTIES_FILE_PATH : generated appilcation.properties file path */
	public static final String GENERATED_APPLICATION_PROPERTIES_FILE_PATH = "src/main/resources/application.properties";
	/** @Fields GENERATED_DB_ENV_FILE_PATH : generated db-env.xml file path */
	public static final String GENERATED_DB_ENV_FILE_PATH = "src/main/resources/application-sharding-tables.properties";
	
	public static final String GENERATED_GRAFANA_DEFAULT_DASHBOARD_PATH = "src/main/scripts/grafana/default_dashboard.json";

}
