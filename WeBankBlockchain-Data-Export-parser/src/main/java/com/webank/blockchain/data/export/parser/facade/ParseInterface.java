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
package com.webank.blockchain.data.export.parser.facade;

import java.io.IOException;

import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;

import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;

/**
 * ParseInterface
 *
 * @Description: ParseInterface
 * @author maojiayu
 * @data Jul 3, 2019 10:49:08 AM
 *
 */
public interface ParseInterface {

    public BlockInfoBO parse(Block block) throws IOException;

}
