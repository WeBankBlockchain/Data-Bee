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
package com.webank.blockchain.data.export.db.vo;

import javax.validation.constraints.NotBlank;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * TxFromQueryReq
 *
 * @Description: TxFromQueryReq as a request object for querying block tx detail info list by tx from
 * @author graysonzhang
 * @data 2019-01-04 14:13:58
 *
 */
@Data
@Accessors(chain = true)
@EqualsAndHashCode(callSuper=true)
public class TxFromQueryReq extends CommonPageReq {
    
    /** @Fields txFrom : tx from */
    @NotBlank
    private String txFrom;
    
    /**    
     * @Description: TxFromQueryReq translates to CommonParaQueryPageReq   
     * @param: @return      
     * @return: CommonParaQueryPageReq       
     */
    public CommonParaQueryPageReq toCommonParaQueryPageReq() {
        CommonParaQueryPageReq<String> req = new CommonParaQueryPageReq<>();
        req.setReqParaName("txFrom").setReqParaValue(this.txFrom).setOrder(this.getOrder())
                .setOrderBy(this.getOrderBy()).setPageNo(this.getPageNo()).setPageSize(this.getPageSize());
        return req;
    }

}
