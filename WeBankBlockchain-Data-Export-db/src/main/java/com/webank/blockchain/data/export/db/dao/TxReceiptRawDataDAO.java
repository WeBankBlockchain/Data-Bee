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
package com.webank.blockchain.data.export.db.dao;

import cn.hutool.core.bean.BeanUtil;
import com.webank.blockchain.data.export.common.bo.data.TxReceiptRawDataBO;
import com.webank.blockchain.data.export.db.entity.TxReceiptRawData;
import com.webank.blockchain.data.export.db.repository.TxReceiptRawDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Component
public class TxReceiptRawDataDAO implements SaveInterface<TxReceiptRawDataBO>{

    @Autowired
    private TxReceiptRawDataRepository txRawDataRepository;

    public void save(TxReceiptRawData txReceiptRawData) {
        BaseDAO.saveWithTimeLog(txRawDataRepository, txReceiptRawData);
    }

    public void save(List<TxReceiptRawDataBO> txReceiptRawDataBOList) {
        txReceiptRawDataBOList.forEach(this :: save);
    }

    @Override
    public void save(TxReceiptRawDataBO txReceiptRawDataBO) {
        TxReceiptRawData txReceiptRawData = new TxReceiptRawData();
        BeanUtil.copyProperties(txReceiptRawDataBO,txReceiptRawData,true);
        save(txReceiptRawData);
    }
}
