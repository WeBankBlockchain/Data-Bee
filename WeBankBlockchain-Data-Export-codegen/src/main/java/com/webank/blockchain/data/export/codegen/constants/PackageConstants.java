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
 * PackageConstants
 *
 * @Description: PackageConstants
 * @author graysonzhang
 * @data 2018-11-9 14:48:45
 *
 */
public class PackageConstants {
    // project package name define
    public static final String PROJECT_PKG_NAME = "blockchain.data.export";
    public static final String SUB_PROJECT_PKG_CORE = "core";
    public static final String SUB_PROJECT_PKG_PARSER = "parser";
    public static final String SUB_PROJECT_PKG_DB = "db";


    public static final String GENERATED = "generated";

    // event package postfix
    public static final String EVENT_BO_PACKAGE_POSTFIX = "bo.event";
    public static final String DB_EVENT_ENTRY_PACKAGE_POSTFIX = "entity.event";
    public static final String DB_EVENT_REPOSITORY_PACKAGE_POSTFIX = "repository.event";
    public static final String CRAWLER_EVENT_IMPL_PACKAGE_POSTFIX = "crawler.event";

    // method package postfix
    public static final String METHOD_BO_PACKAGE_POSTFIX = "bo.method";
    public static final String DB_METHOD_ENTRY_PACKAGE_POSTFIX = "entity.method";
    public static final String DB__METHOD_REPOSITORY_PACKAGE_POSTFIX = "repository.method";
    public static final String CRAWLER_METHOD_IMPL_PACKAGE_POSTFIX = "crawler.method";

}
