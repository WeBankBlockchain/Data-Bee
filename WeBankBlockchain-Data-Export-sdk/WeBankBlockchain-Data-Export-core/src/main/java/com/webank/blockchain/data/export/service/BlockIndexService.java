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

import cn.hutool.core.date.DateUtil;
import com.google.common.base.Stopwatch;
import com.webank.blockchain.data.export.common.entity.DataExportContext;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.tools.DateUtils;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * BlockIndexService
 *
 * @Description: BlockIndexService
 * @author graysonzhang
 * @data 2019-03-25 20:55:07
 *
 */
@Slf4j
public class BlockIndexService {

    public static long getStartBlockIndex() throws IOException, InterruptedException {
        DataExportContext context = ExportConstant.getCurrentContext();
        ExportConfig config = context.getConfig();
        if (config.getStartBlockHeight() > 0) {
            return config.getStartBlockHeight();
        }
        if (config.getStartDate() != null && config.getStartDate().length() > 0) {
            log.info("startDate : {}", config.getStartDate());
            Date startDate = DateUtil.parse(config.getStartDate());
            long blockIndex = -1;
            while ((blockIndex = getBlockIndexByStartDate(startDate)) < 0) {
                Thread.sleep(config.getFrequency() * 1000);
            }
            return blockIndex;
        }
        return 0;
    }

    /**
     * getBlockIndexByStartDate
     * 
     * @param startDate
     * @throws IOException
     * @return long
     */
    private static long getBlockIndexByStartDate(Date startDate) throws IOException {
        DataExportContext context = ExportConstant.getCurrentContext();
        Block beginBlock = getBlock(new BigInteger("0"));
        BigInteger blockNumber = context.getClient().getBlockNumber().getBlockNumber();
        Block endBlock = getBlock(blockNumber);

        Date beginDate = DateUtils.hexStrToDate(beginBlock.getTimestamp());
        Date endDate = DateUtils.hexStrToDate(endBlock.getTimestamp());

        if (beginDate.getTime() > startDate.getTime()) {
            return 0;
        }
        if (endDate.getTime() < startDate.getTime()) {
            return -1;
        }

        return searchBlockIndex(0, blockNumber.longValue(), startDate);
    }

    /**
     * searchBlockIndex: find block index by startDate
     * 
     * @param begin
     * @param end
     * @param startDate
     * @throws IOException
     * @return long
     */
    private static long searchBlockIndex(long begin, long end, Date startDate) throws IOException {
        long index = (begin + end) / 2;
        Block indexBlock = getBlock(new BigInteger(Long.toString(index)));
        Date indexDate = DateUtils.hexStrToDate(indexBlock.getTimestamp());
        if (indexDate.getTime() == startDate.getTime()) {
            return index;
        } else if (indexDate.getTime() > startDate.getTime()) {
            if (index == begin + 1) {
                return index;
            } else {
                return searchBlockIndex(begin, index, startDate);
            }
        } else {
            if (index == end - 1) {
                return end;
            } else {
                return searchBlockIndex(index, end, startDate);
            }
        }
    }

    public static Block getBlock(BigInteger blockHeightNumber) throws IOException {
        Stopwatch stopwatch = Stopwatch.createStarted();
        log.debug("get block number: {}", blockHeightNumber);
        DataExportContext context = ExportConstant.getCurrentContext();
        Block block = context.getClient().getBlockByNumber(blockHeightNumber, true).getBlock();
        Stopwatch st1 = stopwatch.stop();
        log.info("get block:{} succeed, eth.getBlock useTime: {}", blockHeightNumber,
                st1.elapsed(TimeUnit.MILLISECONDS));
        return block;
    }

}