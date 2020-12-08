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
 * TemplateConstants
 *
 * @Description: TemplateConstants
 * @author graysonzhang
 * @data 2018-11-12 16:20:46
 *
 */
public class TemplateConstants {

    /** @Fields CRAWLER_EVENT_IMPL_TEMPLATE_PATH : crawler event impl template path */
    public static final String CRAWLER_EVENT_IMPL_TEMPLATE_PATH = "templates/crawler/crawler_event_impl_template.txt";
    /** @Fields CRAWLER_METHOD_IMPL_TEMPLATE_PATH : crawler method impl template path */
    public static final String CRAWLER_METHOD_IMPL_TEMPLATE_PATH = "templates/crawler/crawler_method_impl_template.txt";

    public static final String EVENT_BO_TEMPLATE_PATH = "templates/bo/event_bo_template.txt";
    public static final String METHOD_BO_TEMPLATE_PATH = "templates/bo/method_bo_template.txt";

    /** @Fields DB_EVENT_ENTITY_TEMPLATE_PATH : event entity template path */
    public static final String DB_EVENT_ENTITY_TEMPLATE_PATH = "templates/db/db_event_entity_template.txt";
    /** @Fields DB_EVENT_REPOSITORY_TEMPLATE_PATH : event repository template path */
    public static final String DB_EVENT_REPOSITORY_TEMPLATE_PATH = "templates/db/db_event_repository_template.txt";
    /** @Fields SQL_EVENT_TEMPLATE_PATH : event sql template path */
    public static final String SQL_EVENT_TEMPLATE_PATH = "templates/db/sql_event_template.sql";

    /** @Fields DB_METHOD_ENTITY_TEMPLATE_PATH : method entity template path */
    public static final String DB_METHOD_ENTITY_TEMPLATE_PATH = "templates/db/db_method_entity_template.txt";
    /** @Fields DB_MEHTOD_REPOSITORY_TEMPLATE_PATH : method repository template path */
    public static final String DB_MEHTOD_REPOSITORY_TEMPLATE_PATH = "templates/db/db_method_repository_template.txt";
    /** @Fields SQL_METHOD_TEMPLATE_PATH : method sql template path */
    public static final String SQL_METHOD_TEMPLATE_PATH = "templates/db/sql_method_template.sql";

    /** @Fields APPLICATION_PROPERTIES_PATH : applicaiton properties path */
    public static final String APPLICATION_PROPERTIES_PATH = "templates/config/application_properties.txt";
    /** @Fields DB_PROPERTIES_PATH : db properties path */
    public static final String DB_PROPERTIES_PATH = "templates/config/application-sharding-tables.txt";

    public static final String GRAFANA_PANEL_TABLE_PATH = "templates/grafana/panel_table.txt";
    public static final String GRAFANA_DASHBOARD_PATH = "templates/grafana/dashboard_default.txt";

}
