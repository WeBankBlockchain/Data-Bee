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
package com.webank.blockchain.data.export.core.jpa;

import java.util.Date;

import com.webank.blockchain.data.export.core.DataBeeApplicationTests;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.webank.blockchain.data.export.db.repository.BlockTaskPoolRepository;

/**
 * BlockTaskPoolRepositoryTest
 *
 * @Description: BlockTaskPoolRepositoryTest
 * @author maojiayu
 * @data Apr 8, 2019 5:30:43 PM
 *
 */
public class BlockTaskPoolRepositoryTest extends DataBeeApplicationTests {
    @Autowired
    private BlockTaskPoolRepository r;

    @Test
    public void testUpd() {
        r.setSyncStatusByBlockHeight((short)7, new Date(), 20);
    }

}
