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
package com.webank.blockchain.data.export.common.tools;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.HexUtil;
import org.apache.commons.lang3.StringUtils;

import java.util.Date;

/**
 * DateUtils
 *
 * @Description: DateUtils
 * @author maojiayu
 * @data Oct 22, 2020 7:54:07 PM
 *
 */
public class DateUtils {

    public static Date hexStrToDate(String hexString) {
        if (StringUtils.startsWithIgnoreCase(hexString, "0x")) {
            hexString = StringUtils.substring(hexString, 2);
        }
        return DateUtil.date(HexUtil.toBigInteger(hexString).longValue());
    }

}
