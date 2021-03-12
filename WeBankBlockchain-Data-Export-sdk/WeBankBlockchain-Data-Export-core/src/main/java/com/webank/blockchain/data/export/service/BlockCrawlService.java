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
package com.webank.blockchain.data.export.service;

import com.google.common.base.Stopwatch;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.parser.facade.ParseFacade;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

/**
 * BlockCrawlService
 *
 * @Description: BlockCrawlService
 * @author maojiayu
 * @data 2019-07-05 16:06:12
 *
 */
@Slf4j
public class BlockCrawlService {
    /**
     * parse a Block to BlockInfoBO by using parser tools.
     * 
     * @param blockHeight
     * @return BlockInfoBO, which include all the structs of a block containing contract info.
     * @throws IOException
     */
    public static BlockInfoBO parse(long blockHeight) throws IOException {
        BigInteger bigBlockHeight = new BigInteger(Long.toString(blockHeight));
        Block block = getBlock(bigBlockHeight);
        return parse(block);
    }

    public static BlockInfoBO parse(Block block) throws IOException {
        Stopwatch st1 = Stopwatch.createStarted();
        BlockInfoBO blockInfo = ParseFacade.parse(block);
        log.info("bcosCrawlerMap block:{} succeed, bcosCrawlerMap.handleReceipt useTime: {}",
                block.getNumber().longValue(), st1.stop().elapsed(TimeUnit.MILLISECONDS));
        return blockInfo;
    }

    public static Block getBlock(BigInteger blockHeightNumber) throws IOException {
        Stopwatch stopwatch = Stopwatch.createStarted();
        log.debug("get block number: {}", blockHeightNumber);
        Block block = ExportConstant.getCurrentContext().getClient()
                .getBlockByNumber(blockHeightNumber, true).getBlock();
        Stopwatch st1 = stopwatch.stop();
        log.info("get block:{} succeed, eth.getBlock useTime: {}", blockHeightNumber,
                st1.elapsed(TimeUnit.MILLISECONDS));
        return block;
    }

}
