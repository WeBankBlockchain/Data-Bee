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
public class BlockRawData extends IdEntity {

    /** @Fields blockHash : block hash */
    private String blockHash;

    /** @Fields blockHeight : block height */
    private long blockHeight;

    /** @Fields blockTimeStamp : block timestamp */
    private Date blockTimeStamp;

    private String parentHash;

    private String logsBloom;

    private String transactionsRoot;

    private String receiptsRoot;

    private String dbHash;

    private String stateRoot;

    private String sealer;

    private String sealerList;

    private String extraData;

    private String gasLimit;

    private String gasUsed;

    private String signatureList;

    private String transactionList;

    /** @Fields updatetime : depot update time */
    protected Date depotUpdatetime = new Date();

}
