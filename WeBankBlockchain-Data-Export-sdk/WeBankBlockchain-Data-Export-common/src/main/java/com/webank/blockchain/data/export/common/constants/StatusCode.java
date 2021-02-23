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
package com.webank.blockchain.data.export.common.constants;

/**
 * Common Status Code.
 *
 * @author maojiayu
 * @data Dec 28, 2018 5:24:46 PM
 *
 */
public class StatusCode {
    public static int SUCCESS = 0; // 成功
    public static int EXECUTE_ERROR = 2; // 执行错误
    public static int SESSION_EXPIRED = 3; // 会话已经过期，请重新登录
    public static int UNAUTH = 4; // 用户无权限访问
    public static int APP_OUTER_DEPENDENCY_ERROR = 5; // 外部依赖错误
    public static int EXCEPTION_OCCUR = 6; // 发生异常
    public static int PARAMETER_ERROR = 7; // 参数错误
    public static int RESULT_EMPTY = 8; // 不存在请求内容
    public static int STATUS_ERROR = 9; // 状态错误
}
