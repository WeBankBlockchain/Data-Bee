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
package com.webank.blockchain.data.export.core.api.manager;

import com.webank.blockchain.data.export.db.service.UnitBasicQueryService;
import com.webank.blockchain.data.export.db.vo.UnitParaQueryPageReq;
import com.webank.blockchain.data.export.db.vo.UnitQueryPageReq;
import com.webank.blockchain.data.export.db.vo.UnitTimeRangeQueryPageReq;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.common.vo.CommonResponse;

/**
 * EventManager
 *
 * @Description: EventManager
 * @author maojiayu
 * @data Dec 24, 2018 11:44:43 AM
 *
 */
@Service
public class MethodManager {
    @Autowired
    private UnitBasicQueryService unitBasicQueryService;
    private final String type = "MethodRepository";

    public CommonResponse getPageListByReq(UnitParaQueryPageReq<String> req) {
        return unitBasicQueryService.getPageListByReq(req, type);
    }

    public CommonResponse getPageListByReq(UnitTimeRangeQueryPageReq req) {
        return unitBasicQueryService.getPageListByReq(req, type);
    }

    public CommonResponse find(UnitQueryPageReq<String> req) {
        return unitBasicQueryService.find(req, type);
    }

}
