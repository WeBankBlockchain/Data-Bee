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
package com.webank.blockchain.data.export.core.service;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import com.webank.blockchain.data.export.extractor.ods.EthClient;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.core.config.SystemEnvironmentConfig;

import cn.hutool.core.date.DateUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * BlockIndexService
 *
 * @Description: BlockIndexService
 * @author graysonzhang
 * @data 2019-03-25 20:55:07
 *
 */
@Service
@Slf4j
public class BlockIndexService {
    @Autowired
    private Client client;
    @Autowired
    private EthClient ethClient;
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;

    public long getStartBlockIndex() throws ParseException, IOException, InterruptedException {
        if (systemEnvironmentConfig.getStartBlockHeight() > 0) {
            return systemEnvironmentConfig.getStartBlockHeight();
        }
        if (systemEnvironmentConfig.getStartDate() != null && systemEnvironmentConfig.getStartDate().length() > 0) {
            log.info("startDate : {}", systemEnvironmentConfig.getStartDate());
            Date startDate = DateUtil.parse(systemEnvironmentConfig.getStartDate());
            long blockIndex = -1;
            while ((blockIndex = getBlockIndexByStartDate(startDate)) < 0) {
                Thread.sleep(systemEnvironmentConfig.getFrequency() * 1000);
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
    private long getBlockIndexByStartDate(Date startDate) throws IOException {

        Block beginBlock = ethClient.getBlock(new BigInteger("0"));
        BigInteger blockNumber = client.getBlockNumber().getBlockNumber();
        Block endBlock = ethClient.getBlock(blockNumber);

        Date beginDate = new Date(Long.parseLong(beginBlock.getTimestamp()));
        Date endDate = new Date(Long.parseLong(endBlock.getTimestamp()));

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
    private long searchBlockIndex(long begin, long end, Date startDate) throws IOException {
        long index = (begin + end) / 2;
        Block indexBlock = ethClient.getBlock(new BigInteger(Long.toString(index)));
        Date indexDate = new Date(Long.parseLong(indexBlock.getTimestamp()));
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

}