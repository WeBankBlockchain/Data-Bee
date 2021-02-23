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
 * @date 2020/10/26
 */
@EqualsAndHashCode(callSuper = true)
@Data
@Accessors(chain = true)
@ToString(callSuper = true)
public class ContractInfo extends IdEntity {

    protected String abiHash;

    private String contractABI;

    private String contractBinary;

    private short version = 1;

    private String contractName;

    /** @Fields updatetime : depot update time */
    protected Date depotUpdatetime = new Date();
}
