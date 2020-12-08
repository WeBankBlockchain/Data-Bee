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
package com.webank.blockchain.data.export.db.repository;

import org.springframework.data.repository.NoRepositoryBean;

/**
 * RollbackOneInterface
 *
 * @Description: RollbackOneInterface
 * @author maojiayu
 * @data Dec 13, 2018 10:53:39 AM
 *
 */
@NoRepositoryBean
public interface RollbackInterface {
    /**
     * rollback from blockHeight, including blockHeight.
     * 
     * @param blockHeight
     */
    public void rollback(long blockHeight);

    /**
     * rollback from startBlockHeight to endBlockHeight, including startBlockHeight, but not including endBlockHeight.
     * 
     * @param startBlockHeight
     * @param endBlockHeight
     */
    public void rollback(long startBlockHeight, long endBlockHeight);

}
