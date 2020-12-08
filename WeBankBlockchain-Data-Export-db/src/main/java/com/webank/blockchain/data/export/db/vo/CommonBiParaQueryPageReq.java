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
import javax.validation.constraints.NotNull;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * CommonBiParaQueryPageReq
 *
 * @Description: CommonBiParaQueryPageReq
 * @author maojiayu
 * @data Jul 17, 2019 5:14:31 PM
 *
 */
@Data
@Accessors(chain = true)
@EqualsAndHashCode(callSuper = true)
public class CommonBiParaQueryPageReq<T> extends CommonPageReq {

    /** @Fields reqParaName : request para name */
    @NotBlank
    private String reqParaName1;

    /** @Fields reqParaValue : request para value */
    @NotNull
    private T reqParaValue1;

    /** @Fields reqParaName : request para name */
    private String reqParaName2;

    /** @Fields reqParaValue : request para value */
    private T reqParaValue2;

}
