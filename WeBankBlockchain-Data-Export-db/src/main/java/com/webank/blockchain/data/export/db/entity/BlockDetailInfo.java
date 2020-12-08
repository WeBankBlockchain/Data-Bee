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

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

/**
 * BlockDetailInfo entity storage of block detail info.
 *
 * @Description: BlockDetailInfo
 * @author graysonzhang
 * @data 2018-11-14 17:45:16
 *
 */
@SuppressWarnings("serial")
@Data
@Accessors(chain = true)
@Entity(name = "block_detail_info")
@Table(name = "block_detail_info", indexes = { @Index(name = "block_hash", columnList = "block_hash"),
        @Index(name = "block_timestamp", columnList = "block_timestamp") })
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class BlockDetailInfo extends IdEntity {

    /** @Fields blockHeight : block height */
    @Column(name = "block_height", unique = true)
    private long blockHeight;

    /** @Fields blockHash : block hash */
    @Column(name = "block_hash")
    private String blockHash;

    /** @Fields txCount : transaction's count in block */
    @Column(name = "tx_count")
    private short txCount;

    /** @Fields blockTimeStamp : block timestamp */
    @Column(name = "block_timestamp")
    private Date blockTimeStamp;

    /** @Fields status : block process status */
    private short status;

    /** @Fields updatetime : depot update time */
    @UpdateTimestamp
    @Column(name = "depot_updatetime")
    @Temporal(TemporalType.TIMESTAMP)
    protected Date depotUpdatetime;

    public enum Status {
        TODO, COMPLETED
    }
}
