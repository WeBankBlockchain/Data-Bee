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
import lombok.experimental.Accessors;

/**
 * BlockTaskPool
 *
 * @Description: BlockTaskPool
 * @author maojiayu
 * @data Apr 1, 2019 3:04:00 PM
 *
 */
@Data
@Accessors(chain = true)
@Table(name = "block_task_pool", indexes = { @Index(name = "sync_status", columnList = "sync_status"),
        @Index(name = "certainty", columnList = "certainty"),
        @Index(name = "depot_updatetime", columnList = "depot_updatetime") })
@Entity(name = "block_task_pool")
@EqualsAndHashCode(callSuper = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BlockTaskPool extends IdEntity {

    private static final long serialVersionUID = 5987912520917085396L;

    @Column(name = "block_height", unique = true)
    private long blockHeight;

    /** @Fields syncStatus : sync status of transactions */
    @Column(name = "sync_status")
    private short syncStatus;

    /** @Fields certainty : certainty of fork check */
    @Column(name = "certainty")
    private short certainty;

    @Column(name = "handle_item")
    private short handleItem = 0;

    /** @Fields updatetime : update time */
    @UpdateTimestamp
    @Column(name = "depot_updatetime")
    @Temporal(TemporalType.TIMESTAMP)
    protected Date depotUpdatetime;
}
