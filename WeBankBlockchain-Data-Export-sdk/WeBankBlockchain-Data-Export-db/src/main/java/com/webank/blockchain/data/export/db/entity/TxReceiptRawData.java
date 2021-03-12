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
package com.webank.blockchain.data.export.db.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

import java.util.Date;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/23
 */
@Data
@Accessors(chain = true)
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class TxReceiptRawData extends IdEntity{

    /** @Fields blockHeight : block height */
    private long blockHeight;

    /** @Fields blockHash : block hash */
    private String blockHash;

    /** @Fields txHash : transaction hash */
    private String txHash;

    /** @Fields blockTimeStamp : block timestamp */
    private Date blockTimeStamp;

    private String txIndex;

    private String root;

    private String from;

    private String to;

    private String gasUsed;

    private String contractAddress;

    private String logs;

    private String logsBloom;

    private String status;

    private String input;

    private String output;

    private String txProof;

    private String receiptProof;

    private String message;

    /** @Fields updatetime : depot update time */
    protected Date depotUpdatetime = new Date();

}
