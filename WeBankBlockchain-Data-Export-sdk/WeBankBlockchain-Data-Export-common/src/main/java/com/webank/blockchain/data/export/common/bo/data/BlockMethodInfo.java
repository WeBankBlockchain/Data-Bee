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
package com.webank.blockchain.data.export.common.bo.data;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Map;

/**
 * BlockMethodInfo
 *
 * @Description: BlockMethodInfo
 * @author maojiayu
 * @data Jul 3, 2019 2:59:33 PM
 *
 */
@Data
@Accessors(chain = true)
public class BlockMethodInfo {

    private List<BlockTxDetailInfoBO> blockTxDetailInfoList;

    private List<TxRawDataBO> txRawDataBOList;

    private List<TxReceiptRawDataBO> txReceiptRawDataBOList;

    private List<MethodBO> methodInfoList;

    private Map<String, String> txHashContractNameMapping;

}
