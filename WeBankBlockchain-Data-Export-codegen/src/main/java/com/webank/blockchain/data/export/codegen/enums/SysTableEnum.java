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
package com.webank.blockchain.data.export.codegen.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * SysTableEnum
 *
 * @Description: SysTableEnum
 * @author maojiayu
 * @data Jan 7, 2019 8:51:22 PM
 *
 */
@AllArgsConstructor
@Getter
public enum SysTableEnum {
    ACCOUNT_INFO("AccountInfo", "account_info"),
    BLOCK_DETAIL_INFO("BlockDetailInfo", "block_detail_info"),
    BLOCK_INFO("BlockInfo", "block_info"),
    BLOCK_TX_DETAIL_INFO("BlockTxDetailInfo", "block_tx_detail_info")
;
    
    String name;
    String tableName;

}
