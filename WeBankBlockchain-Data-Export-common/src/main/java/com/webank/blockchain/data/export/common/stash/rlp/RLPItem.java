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
package com.webank.blockchain.data.export.common.stash.rlp;

import lombok.Data;


/**
 * RLPItem
 *
 * @Description: RLPItem
 * @author maojiayu
 * @data Sep 25, 2019 4:01:51 PM
 *
 */
@Data
public class RLPItem implements RLPElement {
    
    private static final long serialVersionUID = 7867984796230853830L;
    private final byte[] rlpData;

    public RLPItem(byte[] rlpData) {
        this.rlpData = rlpData;
    }

    public byte[] getRLPData() {
        if (rlpData.length == 0)
            return null;
        return rlpData;
    }
}
