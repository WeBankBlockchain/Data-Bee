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

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.hibernate.annotations.UpdateTimestamp;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

/**
 * BlockTxDetailInfo
 *
 * @Description: BlockTxDetailInfo
 * @author graysonzhang
 * @data 2018-12-20 14:38:18
 *
 */
@SuppressWarnings("serial")
@Data
@Accessors(chain = true)
@Entity(name = "block_tx_detail_info")
@Table(name = "block_tx_detail_info", indexes = { @Index(name = "block_height", columnList = "block_height"),
        @Index(name = "tx_from", columnList = "tx_from"),
        @Index(name = "block_timestamp", columnList = "block_timestamp") })
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BlockTxDetailInfo extends IdEntity {
    
	/** @Fields blockHeight : block height */
	@Column(name = "block_height")
    private long blockHeight;
	
    /** @Fields blockHash : block hash */
    @Column(name = "block_hash")
    private String blockHash;
    
    /** @Fields contractName : contract name */
    @Column(name = "contract_name")
    private String contractName;
    
    /** @Fields methodName : contract method name */
    @Column(name = "method_name")
    private String methodName;
    
    /** @Fields txHash : transaction hash */
    @Column(name = "tx_hash")
    private String txHash;
    
    /** @Fields txFrom : transaction' s from */
    @Column(name = "tx_from")
    private String txFrom;
    
    /** @Fields txTo : transaction's to */
    @Column(name = "tx_to")
    private String txTo;
    
    /** @Fields blockTimeStamp : block timestamp */
    @Column(name = "block_timestamp")
    private Date blockTimeStamp;
    
    /** @Fields updatetime : depot update time */
    @UpdateTimestamp
    @Column(name = "depot_updatetime")
    @Temporal(TemporalType.TIMESTAMP)
    protected Date depotUpdatetime;
}
