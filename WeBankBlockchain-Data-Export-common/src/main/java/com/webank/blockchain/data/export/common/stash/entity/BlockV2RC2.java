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
package com.webank.blockchain.data.export.common.stash.entity;

import cn.hutool.core.util.HexUtil;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.common.entity.DataExportContext;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.stash.rlp.ByteUtil;
import com.webank.blockchain.data.export.common.stash.rlp.RLP;
import com.webank.blockchain.data.export.common.stash.rlp.RLPList;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.utils.Numeric;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * BlockV2RC2
 *
 * @Description: BlockV2RC2
 * @author maojiayu
 * @data Sep 4, 2019 10:35:10 AM
 *
 */
@Data
@EqualsAndHashCode
@Accessors(chain = true)
public class BlockV2RC2 {

    private BlockHeader blockHeader;
    private List<TransactionDetail> transactions;
    private String hash;
    private List<Map<String, String>> sigList;
    private List<TransactionReceipt> trList;
    @JsonIgnore
    private RLPList txReceipts;
    @JsonIgnore
    private RLPList blockHeaderRlp;

    // attention: hexString is no prefix of "0x"
    @SuppressWarnings("unchecked")
    public BlockV2RC2(String hexString) {
        if (hexString.startsWith("0x") || hexString.startsWith("0X")) {
            hexString = hexString.substring(2);
        }
        byte[] b = HexUtil.decodeHex(hexString);
        RLPList params = RLP.decode2(b);
        RLPList block = (RLPList) params.get(0);
        this.blockHeaderRlp = (RLPList) block.get(0);
        this.blockHeader = new BlockHeader((RLPList) block.get(0));
        this.transactions = parseTransactionDetail(block.get(1).getRLPData());
        this.hash = Numeric.toHexString(block.get(2).getRLPData());
        sigList = Lists.newArrayList();
        for (RLPList r : (List<RLPList>) block.get(3)) {
            if (r.get(0).getRLPData() != null) {
                Map<String, String> m = Maps.newHashMap();
                m.put(Hex.encodeHexString(r.get(0).getRLPData()), Hex.encodeHexString(r.get(1).getRLPData()));
                sigList.add(m);
            } else {
                Map<String, String> m = Maps.newHashMap();
                m.put("null", Hex.encodeHexString(r.get(1).getRLPData()));
                sigList.add(m);
            }
        }
        this.txReceipts = (RLPList) block.get(4);
        trList = Lists.newArrayList();
        for (RLPList r : (List<RLPList>) block.get(4)) {
            TransactionReceipt e = new TransactionReceipt(r);
            trList.add(e);
        }
    }

    public static List<TransactionDetail> parseTransactionDetail(byte[] transactions){
        List<TransactionDetail> list = new ArrayList<>();
        if(ArrayUtils.isEmpty(transactions) || transactions.length <  4) {
            return list;
        }
        long count = (int) ByteUtil.byte4UnsignToLong(transactions, 0);
        int offset = (int) (count*4+8);
        int startPos, endPos = 0;
        for(long i=1;i<=count;i++) {
            startPos = (int) ByteUtil.byte4UnsignToLong(transactions, (int) (4*i));
            endPos = (int) ByteUtil.byte4UnsignToLong(transactions, (int) (4*i+4));
            byte[] sub = ByteUtil.subBytes(transactions, offset+startPos, endPos-startPos);
            TransactionDetail t = new TransactionDetail((RLPList) RLP.decode2(sub).get(0));
            t.setHash(Hex.encodeHexString(ExportConstant.getCurrentContext().getClient().getCryptoSuite().hash(sub)));
            list.add(t);
        }
        return list;
    }


}
